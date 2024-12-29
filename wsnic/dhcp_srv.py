##
## dhcp_srv.py
## IPv4 DHCP server.
##
## Links:
## - https://www.rfc-editor.org/rfc/rfc2132.html
## - https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
## - https://github.com/russdill/lwip-udhcpd/blob/master/udhcp_common.c
## - https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol

import struct, socket, functools, enum, time
from collections import namedtuple

from wsnic import Pollable, mac2str

## DhcpPacket.op values
DHCP_OP_NONE = 0
DHCP_OP_REQUEST = 1
DHCP_OP_REPLY = 2

## DhcpPacket.flags bits
DHCP_FLAG_BROADCAST = 1

## Option 53 (DHCP Message Type) values
DHCP_MSG_TYPE_DISCOVER = 1
DHCP_MSG_TYPE_OFFER = 2
DHCP_MSG_TYPE_REQUEST = 3
DHCP_MSG_TYPE_DECLINE = 4
DHCP_MSG_TYPE_ACK = 5
DHCP_MSG_TYPE_NAK = 6
DHCP_MSG_TYPE_RELEASE = 7
DHCP_MSG_TYPE_INFORM = 8

DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'

class OptionType:
    Type = namedtuple('Type', ['typename', 'encode', 'decode'])

    @staticmethod
    def str_encode(code, val):
        val = val.encode()
        return struct.pack(f'!BB{len(val)}s', code, len(val), val)

    @staticmethod
    def ipv4_array_encode(code, val_array):
        val_array = [val_array] if isinstance(val_array, str) else val_array
        result = bytearray(struct.pack(f'!BB', code, len(val_array)*4))
        for val in val_array:
            result.extend(socket.inet_aton(val))
        return result

    @staticmethod
    def ipv4_array_decode(data, ofs, len):
        result = []
        end = ofs + len
        while ofs < end:
            result.append(socket.inet_ntoa(data[ofs : ofs+4]))
            ofs += 4
        return result

    uint8_t = Type('uint8',
        lambda code,val: struct.pack('!BBB', code, 1, val),
        lambda data,ofs,len: data[ofs])
    uint16_t = Type('uint16',
        lambda code,val: struct.pack('!BBH', code, 2, val),
        lambda data,ofs,len: struct.unpack_from('!H', data, offset=ofs)[0])
    int32_t = Type('int32',
        lambda code,val: struct.pack('!BBi', code, 4, val),
        lambda data,ofs,len: struct.unpack_from('!i', data, offset=ofs)[0])
    uint32_t = Type('uint32',
        lambda code,val: struct.pack('!BBI', code, 4, val),
        lambda data,ofs,len: struct.unpack_from('!I', data, offset=ofs)[0])
    bytes_t = Type('bytes',
        lambda code,val: struct.pack(f'!BB{len(val)}p', code, len(val), val),
        lambda data,ofs,len: data[ofs : ofs+len])
    uint8_array_t = Type('uint8[]',
        lambda code,val: struct.pack(f'!BB{len(val)}B', code, len(val), val),
        lambda data,ofs,len: list(data[ofs : ofs+len]))
    str_t = Type('str',
        str_encode,
        lambda data,ofs,len: data[ofs : ofs+len].rstrip(b'\0').decode())
    ipv4_t = Type('ipv4',
        lambda code,val: struct.pack(f'!BB4s', code, 4, socket.inet_aton(val)),
        lambda data,ofs,len: socket.inet_ntoa(data[ofs : ofs+4]))
    ipv4_array_t = Type('ipv4[]',
        ipv4_array_encode,
        ipv4_array_decode)

class OptionEnum(enum.Enum):
    def __new__(cls, value, opt_type):
        member = object.__new__(cls)
        member._value_ = value
        member.typename = opt_type.typename
        member.decode = opt_type.decode
        member.encode = functools.partial(opt_type.encode, value)
        return member

    SUBNET_MASK     = 1,   OptionType.ipv4_t
    TIME_OFFSET     = 2,   OptionType.int32_t
    ROUTER_IPS      = 3,   OptionType.ipv4_array_t
    DNS_IPS         = 6,   OptionType.ipv4_array_t
    HOSTNAME        = 12,  OptionType.str_t
    DOMAIN_NAME     = 15,  OptionType.str_t
    MTU             = 26,  OptionType.uint16_t
    BROADCAST_IP    = 28,  OptionType.ipv4_t
    NTP_IPS         = 42,  OptionType.ipv4_array_t
    NETBIOS_NS_IPS  = 44,  OptionType.ipv4_array_t
    NETBIOS_SCOPE   = 47,  OptionType.bytes_t
    REQUESTED_IP    = 50,  OptionType.ipv4_t
    LEASE_TIME      = 51,  OptionType.uint32_t
    MSG_TYPE        = 53,  OptionType.uint8_t
    SERVER_ID       = 54,  OptionType.ipv4_t
    REQ_PARAM_LIST  = 55,  OptionType.uint8_array_t
    MAX_MSG_SIZE    = 57,  OptionType.uint16_t
    RENEWAL_TIME    = 58,  OptionType.uint32_t
    REBINDING_TIME  = 59,  OptionType.uint32_t
    VENDOR_CLS_ID   = 60,  OptionType.str_t
    CLIENT_ID       = 61,  OptionType.bytes_t
    DOMAIN_SEARCH   = 119, OptionType.str_t
    CLASSLESS_ROUTE = 121, OptionType.bytes_t

class DhcpPacket:
    def __init__(self):
        self.op = DHCP_OP_NONE  ## either DHCP_OP_REQUEST or DHCP_OP_REPLY
        self.htype = 0          ## hardware address type, 1=Ethernet
        self.hlen = 0           ## hardware address length
        self.hops = 0           ## number of relay agents a request message traveled
        self.xid = 0            ## transaction ID, random number chosen by client to identify an IP address allocation
        self.secs = 0           ## number of seconds elapsed since client began allocation or renewal
        self.flags = 0          ## bit 0x01: BROADCAST flag, set when server sends reply by broadcast
        self.ciaddr = '0.0.0.0' ## client IP address: non-zero only if the client has a valid IP address
        self.yiaddr = '0.0.0.0' ## your IP address: IP address assigned by the DHCP server to the client
        self.siaddr = '0.0.0.0' ## server IP address
        self.giaddr = '0.0.0.0' ## gateway IP address: IP address of the first relay agent
        self.chaddr = b''       ## client hardware address
        self.sname = ''         ## server host name
        self.filename = ''      ## boot file name
        self.options = {}       ## dict(OptionEnum opt_enum => opt_val)

    def copy(self):
        pkt = DhcpPacket()
        for var in vars(self):
            if var != 'options':
                setattr(pkt, var, getattr(self, var))
        return pkt

    def dump(self, prefix):
        print(f'{prefix}: op={self.op} htype={self.htype} hlen={self.hlen} ' \
            f'hops={self.hops} xid={hex(self.xid)} secs={self.secs} ' \
            f'flags={self.flags} ciaddr={self.ciaddr} yiaddr={self.yiaddr} ' \
            f'siaddr={self.siaddr} giaddr={self.giaddr} chaddr={self.chaddr.hex()} ' \
            f'sname={self.sname} filename={self.filename}\n  options={self.options}')

    def to_bytes(self):
        result = bytearray(struct.pack('!BBBBIHH4s4s4s4s16s64s128s4s', self.op, self.htype,
            self.hlen, self.hops, self.xid, self.secs, self.flags,
            socket.inet_aton(self.ciaddr), socket.inet_aton(self.yiaddr),
            socket.inet_aton(self.siaddr), socket.inet_aton(self.giaddr),
            self.chaddr, self.sname.encode(), self.filename.encode(), DHCP_MAGIC_COOKIE))
        for opt_enum, opt_val in self.options.items():
            #print(f'DHCP: encoding option {opt_enum.name} ({opt_enum.value}) val={opt_val}')
            result.extend(opt_enum.encode(opt_val))
        result.extend(b'\xff')
        return result

    @classmethod
    def from_bytes(cls, data):
        pkt = DhcpPacket()
        pkt.op, pkt.htype, pkt.hlen, pkt.hops, pkt.xid, pkt.secs, pkt.flags, \
                ciaddr, yiaddr, siaddr, giaddr, pkt.chaddr, \
                sname, filename, magic_cookie = \
            struct.unpack('!BBBBIHH4s4s4s4s16s64s128s4s', data[ : 240 ])

        if magic_cookie != DHCP_MAGIC_COOKIE:
            print('DHCP: package with invalid magic cookie refused')
            return None
        elif pkt.op != DHCP_OP_REQUEST:
            print('DHCP: non-request package refused')
            return None

        pkt.ciaddr = socket.inet_ntoa(ciaddr)
        pkt.yiaddr = socket.inet_ntoa(yiaddr)
        pkt.siaddr = socket.inet_ntoa(siaddr)
        pkt.giaddr = socket.inet_ntoa(giaddr)
        pkt.sname = sname.rstrip(b'\0').decode()
        pkt.filename = filename.rstrip(b'\0').decode()

        opt_data = data[ 240 : ]
        opt_cursor = 0
        while opt_cursor < len(opt_data):
            opt_code = opt_data[opt_cursor]
            opt_cursor += 1
            if opt_code == 0: ## Pad option
                continue
            elif opt_code == 255: ## End option
                break
            opt_len = opt_data[opt_cursor]
            opt_cursor += 1
            try:
                opt_enum = OptionEnum(opt_code)
            except ValueError:
                print(f'DHCP: {opt_cursor}: note: skipping unknown Option opt_code={opt_code} opt_len={opt_len}')
            else:
                opt_val = opt_enum.decode(opt_data, opt_cursor, opt_len)
                pkt.options[opt_enum] = opt_val
                #print(f'DHCP: {opt_cursor}: decoded option opt_code={opt_enum.name} ({opt_code}) opt_len={opt_len} opt_val={opt_val}')
            opt_cursor += opt_len
        return pkt

class DhcpServer(Pollable):
    IGNORED_OPTIONS = [
        OptionEnum.HOSTNAME, OptionEnum.NTP_IPS, OptionEnum.TIME_OFFSET,
        OptionEnum.DOMAIN_SEARCH, OptionEnum.NETBIOS_NS_IPS,
        OptionEnum.NETBIOS_SCOPE, OptionEnum.CLASSLESS_ROUTE ]

    def __init__(self, server):
        super().__init__(server)
        self.dhcp_network = server.dhcp_network
        self.sock = None

    def open(self, iface):
        print(f'DHCP: server listening on interface {iface}')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        self.sock.bind(('', 67))    ## 67: DHCP server, 68: DHCP client
        self.sock.setblocking(0)
        super().open(self.sock.fileno())

    def close(self):
        super().close()
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            print(f'DHCP: server closed')

    def recv_ready(self):
        data, addr = self.sock.recvfrom(65535)

        pkt_in = DhcpPacket.from_bytes(data)
        if not pkt_in:
            print(f'DHCP: non-DHCP packet dropped')
            return

        #print()
        #pkt_in.dump(f'{addr[0]}:{addr[1]}: RECV[{len(data)}]')

        reply_msg_type = None
        client_mac = pkt_in.chaddr[ : pkt_in.hlen ]
        client_ip = None

        request_msg_type = pkt_in.options[OptionEnum.MSG_TYPE]
        if request_msg_type == DHCP_MSG_TYPE_DISCOVER:
            client_ip = self.dhcp_network.reserve_address(client_mac)
            if client_ip:
                reply_msg_type = DHCP_MSG_TYPE_OFFER
        elif request_msg_type == DHCP_MSG_TYPE_REQUEST:
            client_ip = self.dhcp_network.find_address(client_mac)
            if client_ip:
                reply_msg_type = DHCP_MSG_TYPE_ACK
                self.dhcp_network.assign_address(client_mac)
        elif request_msg_type == DHCP_MSG_TYPE_DECLINE:
            pass
        elif request_msg_type == DHCP_MSG_TYPE_RELEASE:
            self.dhcp_network.release_address(client_mac)
        elif request_msg_type == DHCP_MSG_TYPE_INFORM:
            pass
        else:
            print(f'DHCP: packet with unexpected Message Type Option {request_msg_type} dropped')
            return

        if reply_msg_type is None:
            return

        pkt_out = pkt_in.copy()
        pkt_out.op = DHCP_OP_REPLY
        pkt_out.flags |= DHCP_FLAG_BROADCAST
        pkt_out.yiaddr = client_ip
        pkt_out.siaddr = self.config.bridge_addr
        pkt_out.giaddr = self.config.dhcp_gateway

        pkt_out.options[OptionEnum.MSG_TYPE] = reply_msg_type
        pkt_out.options[OptionEnum.SUBNET_MASK] = self.config.netmask
        pkt_out.options[OptionEnum.ROUTER_IPS] = self.config.bridge_addr
        pkt_out.options[OptionEnum.SERVER_ID] = self.config.bridge_addr
        pkt_out.options[OptionEnum.BROADCAST_IP] = self.config.broadcast_addr
        pkt_out.options[OptionEnum.LEASE_TIME] = self.config.dhcp_lease_time
        pkt_out.options[OptionEnum.RENEWAL_TIME] = self.config.dhcp_lease_time // 2
        pkt_out.options[OptionEnum.REBINDING_TIME] = self.config.dhcp_lease_time * 7 // 8
        pkt_out.options[OptionEnum.MTU] = 1500

        if self.config.dhcp_domain_name:
            pkt_out.options[OptionEnum.DOMAIN_NAME] = self.config.dhcp_domain_name
        if self.config.dhcp_domain_name_server:
            pkt_out.options[OptionEnum.DNS_IPS] = self.config.dhcp_domain_name_server
        if OptionEnum.HOSTNAME in pkt_in.options:
            pkt_out.options[OptionEnum.HOSTNAME] = pkt_in.options[OptionEnum.HOSTNAME]

        if OptionEnum.REQ_PARAM_LIST in pkt_in.options:
            for opt_code in pkt_in.options[OptionEnum.REQ_PARAM_LIST]:
                try:
                    opt_enum = OptionEnum(opt_code)
                except ValueError:
                    print(f'DHCP: skipped requested Option with unknown code {opt_code}')
                else:
                    if opt_enum not in pkt_out.options and opt_enum not in self.IGNORED_OPTIONS:
                        print(f'DHCP: skipped requested Option {opt_enum}')

        bytes_out = pkt_out.to_bytes()
        #print()
        #pkt_out.dump(f'255.255.255.255:68: SEND[{len(bytes_out)}]')

        self.sock.sendto(bytes_out, ('255.255.255.255', 68))

class DhcpNetwork:
    class Host:
        def __init__(self, ip):
            self.ip = ip
            self.mac = None
            self.reserved_tm = 0
            self.is_assigned = False

    def __init__(self, config):
        self.mac2host = {}  ## dict(bytes mac[6] => Host host, ...)
        self.hosts = [self.Host(addr) for addr in config.host_addrs]

    def reserve_address(self, mac):
        selected_host = None
        if mac in self.mac2host:
            selected_host = self.mac2host[mac]
        else:
            for host in self.hosts:
                if host.is_assigned:
                    continue
                elif selected_host is None or host.reserved_tm < selected_host.reserved_tm:
                    selected_host = host
        if selected_host is None:
            return None
        elif selected_host.mac != mac:
            if selected_host.mac is not None and selected_host.mac in self.mac2host:
                del self.mac2host[selected_host.mac]
            self.mac2host[mac] = selected_host
            selected_host.mac = mac
        selected_host.reserved_tm = time.time()
        return selected_host.ip

    def find_address(self, mac):
        return self.mac2host[mac].ip if mac in self.mac2host else None

    def assign_address(self, mac):
        if mac in self.mac2host:
            host = self.mac2host[mac]
            if host.is_assigned:
                print(f'DHCP: re-assigned IP address {host.ip} to MAC {mac2str(mac)}')
            else:
                host.is_assigned = True
                print(f'DHCP: assigned IP address {host.ip} to MAC {mac2str(mac)}')

    def release_address(self, mac):
        if mac in self.mac2host:
            host = self.mac2host[mac]
            if host.is_assigned:
                host.is_assigned = False
                print(f'DHCP: released IP address {host.ip}')
