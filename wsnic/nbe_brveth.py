##
## nbe_brveth.py
## Network backend: Network bridge with one veth-pair and an AF_PACKET-Socket per WebSocket client.
##

import os, logging, struct, fcntl, socket

from wsnic import Pollable, NetworkBackend, FrameQueue, run, mac2str, log_eth_frame
#from wsnic.dhcp import DhcpServer
from wsnic.nbe_brtap import BridgedTapNetworkBackend

logger = logging.getLogger('nbe_brveth')

SIOCSIFADDR    = 0x00008916
SIOCSIFNETMASK = 0x0000891C
SIOCSIFHWADDR  = 0x00008924

ETH_P_ALL = 0x0003
#ETH_P_ALL = 0x0800

class BridgedVethNetworkBackend(BridgedTapNetworkBackend):
    def __init__(self, server):
        super().__init__(server)

    def forward_from_ws_client(self, ws_client, eth_frame):
        if not ws_client.mac_addr:
            dst_mac, src_mac = struct.unpack_from('6s6s', eth_frame)
            self.set_client_mac(ws_client, src_mac)
            ## ws_client.pkt_sink is an instance of BridgedVethCLient
            logger.info(f'assigning VM MAC {mac2str(src_mac)} to {ws_client.pkt_sink.veth_vm_iface}')
            ws_client.pkt_sink.set_mac_addr(src_mac)
            logger.info(f'{ws_client.addr}: registered MAC address {mac2str(src_mac)}')
        super().forward_from_ws_client(ws_client, eth_frame)

    def dhcp_lease_assigned(self, mac_addr, ip_addr):
        print(f'==> {mac2str(mac_addr)} <-> {ip_addr}')

    def _create_pollable(self, ws_client):
        return BridgedVethCLient(self.server, ws_client)

class BridgedVethCLient(Pollable):
    INSTANCE_COUNTER = 0

    def __init__(self, server, ws_client):
        super().__init__(server)
        self.ws_client = ws_client            ## WebSocketClient, the associated ws_client
        self.out = FrameQueue()               ## frames waiting to be send
        self.br_iface = server.netbe.br_iface ## the bridge's interface name, for example 'wsnicbr0'
        self.veth_br_iface = None             ## the bridge-side of the veth pair, for example vethbr0
        self.veth_vm_iface = None             ## the vm-side of the veth pair, for example vethvm0
        self.sock = None                      ## our local packet socket

    def set_mac_addr(self, mac_addr):
        """
        ifreq = struct.pack('16sH6B8x', self.veth_vm_iface.encode(), socket.AF_INET, *mac_addr)
        fcntl.ioctl(self.fd, SIOCSIFHWADDR, ifreq)
        """
        # ip link set dev <self.veth_vm_iface> down
        # ip link set dev <self.veth_vm_iface> address <mac2str(mac_addr)>
        # ip link set dev <self.veth_vm_iface> up

        """
        super().close()
        if self.sock:
            self.sock.close()
            self.sock = None

        run(['ip', 'link', 'set', self.veth_vm_iface, 'down'], logger, check=True)
        run(['ip', 'link', 'set', self.veth_vm_iface, 'addr', mac2str(mac_addr)], logger, check=True)
        run(['ip', 'link', 'set', self.veth_vm_iface, 'up'], logger, check=True)

        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((self.veth_vm_iface, 0))
        super().open(self.sock.fileno())
        """

        #run(['ip', 'link', 'set', self.veth_vm_iface, 'addr', mac2str(mac_addr)], logger, check=True)
        pass

    def set_ip_and_netmask(self, ip_addr, netmask):
        vm_iface = self.veth_vm_iface.encode()
        ifreq = struct.pack('16sH2s4s8s', vm_iface, socket.AF_INET, b'\x00'*2, socket.inet_aton(ip_addr), b'\x00'*8)
        fcntl.ioctl(self.fd, SIOCSIFADDR, ifreq)
        ifreq = struct.pack('16sH2s4s8s', vm_iface, socket.AF_INET, b'\x00'*2, socket.inet_aton(netmask), b'\x00'*8) 
        fcntl.ioctl(self.fd, SIOCSIFNETMASK, ifreq)

    def open(self):
        ## generate distinct interface names for the veth pair
        self.veth_br_iface = f'vethbr{BridgedVethCLient.INSTANCE_COUNTER}'
        self.veth_vm_iface = f'vethvm{BridgedVethCLient.INSTANCE_COUNTER}'
        BridgedVethCLient.INSTANCE_COUNTER += 1

        ## create veth pair, connect veth pair's bridge-side to bridge
        run(['ip', 'link', 'add', self.veth_br_iface, 'type', 'veth', 'peer', 'name', self.veth_vm_iface], logger, check=True)
        run(['ip', 'link', 'set', self.veth_br_iface, 'mtu', '1500'], logger, check=True)
        run(['ip', 'link', 'set', self.veth_vm_iface, 'mtu', '1500'], logger, check=True)
        run(['ip', 'link', 'set', self.veth_vm_iface, 'promisc', 'on'], logger, check=True)
        """
        ip link set dev vethvm0 mtu 1500
        ip link set dev vethbr0 mtu 1500
        """
        run(['ip', 'link', 'set', self.veth_br_iface, 'master', self.br_iface], logger, check=True)
        run(['ip', 'link', 'set', self.veth_br_iface, 'up'], logger, check=True)
        #run(['ip', 'addr', 'add', '192.168.2.2/24', 'brd', '+', 'dev', self.veth_vm_iface], logger, check=True)
        run(['ip', 'link', 'set', self.veth_vm_iface, 'up'], logger, check=True)

        ## open and connect packet socket to veth pair's vm-side
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((self.veth_vm_iface, 0))

        super().open(self.sock.fileno())
        logger.info(f'created veth pair ({self.veth_br_iface}, {self.veth_vm_iface})')

    def close(self):
        super().close()
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.info(f'destroyed veth pair ({self.veth_br_iface}, {self.veth_vm_iface})')
        if self.veth_br_iface:
            run(['ip', 'link', 'del', self.veth_br_iface], logger, check=True)

    def send(self, eth_frame):
        if len(eth_frame):
            was_empty = self.out.is_empty()
            self.out.append(eth_frame)
            if was_empty:
                self.wants_send(True)

    def send_ready(self):
        eth_frame = self.out.get_frame()
        if eth_frame is None:
            self.wants_send(False)
        else:
            self.out.trim_frame(self.sock.send(eth_frame))
            #log_eth_frame('ws->veth', eth_frame, logger)

    def recv_ready(self):
        eth_frame = self.sock.recv(65535)
        self.ws_client.send(eth_frame)
        #log_eth_frame('veth->ws', eth_frame, logger)
        """
        eth_frame, addr = self.sock.recvfrom(65535)

        # recv_ready(): ('vethvm0', 34525, 2, 1, b'\x00\n\xe7\xbe\xee\xef')
        logger.info(f'recv_ready(): {addr}')
        sll_pkttype = struct.unpack('H', addr[4][14:16])[0]  # Extract sll_pkttype from sockaddr_ll

        if sll_pkttype == PACKET_OUTGOING:
            print("Outgoing packet (sent by this host) dropped")
        else:
            self.ws_client.send(eth_frame)
            log_eth_frame('veth->ws', eth_frame, logger)
        """
