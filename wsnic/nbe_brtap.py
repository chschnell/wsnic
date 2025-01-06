##
## nbe_brtap.py
## Network backend: Network bridge with one Linux TAP device per WebSocket client.
##

import os, logging, struct, fcntl

from wsnic import Pollable, NetworkBackend, FrameQueue, Exec, mac2str, random_private_mac

logger = logging.getLogger('brtap')

TAP_CLONE_DEV = '/dev/net/tun'
TUNSETIFF     = 0x400454ca
IFF_UP        = 0x1
IFF_TAP       = 0x0002
IFF_NO_PI     = 0x1000

class BridgedTapNetworkBackend(NetworkBackend):
    ## - maintains one TAP device per ws_client
    ##
    def __init__(self, server):
        super().__init__(server)
        self.br_iface = 'wsbr0'
        self.eth_iface = self.config.eth_iface
        self.dhcp_server = None
        self.is_opened = False
        self.restrict_inbound = True

    def _install_nat_rules(self, do_install):
        cmd = '-A' if do_install else '-D'
        run = Exec(logger, check=do_install)
        run(f'iptables {cmd} POSTROUTING -t nat -o {self.eth_iface} -j MASQUERADE')
        if self.restrict_inbound:
            run(f'iptables {cmd} FORWARD -i {self.eth_iface} -o {self.br_iface} -m state --state RELATED,ESTABLISHED -j ACCEPT')
        else:
            run(f'iptables {cmd} FORWARD -i {self.eth_iface} -o {self.br_iface} -j ACCEPT')

        run(f'iptables {cmd} FORWARD -i {self.br_iface} -o {self.eth_iface} -d {self.config.subnet} -j DROP')
        run(f'iptables {cmd} FORWARD -i {self.br_iface} -o {self.eth_iface} -j ACCEPT')

    def open(self):
        if self.is_opened:
            return
        self.is_opened = True
        ## create bridge
        run = Exec(logger, check=True)
        run(f'ip link add dev {self.br_iface} type bridge')
        #run(f'sysctl net.ipv6.conf.{self.br_iface}.disable_ipv6=1')
        run(f'ip link set dev {self.br_iface} address {mac2str(random_private_mac())}')
        run(f'ip addr add dev {self.br_iface} {self.config.server_addr}/{self.config.netmask} brd +')
        #run(f'ip link set dev {self.br_iface} promisc on')
        run(f'ip link set dev {self.br_iface} up')

        ## setup bridge NAT rules
        self._install_nat_rules(True)
        logger.info(f'created bridge {self.br_iface}')
        ## install DHCP server on bridge
        self.dhcp_server = self.server.create_dhcp_server()
        if self.dhcp_server:
            self.dhcp_server.open(self.br_iface)

    def close(self):
        if not self.is_opened:
            return
        if self.dhcp_server:
            self.dhcp_server.close()
            self.dhcp_server = None
        self._install_nat_rules(False)
        Exec(logger)(f'ip link del {self.br_iface}')
        logger.info(f'destroyed bridge {self.br_iface}')
        self.is_opened = False

    def attach_client(self, ws_client):
        tap_dev = self._create_pollable(ws_client)
        tap_dev.open()
        ws_client.pkt_sink = tap_dev
        super().attach_client(ws_client)

    def detach_client(self, ws_client):
        if ws_client.pkt_sink:
            ws_client.pkt_sink.close()
            ws_client.pkt_sink = None
        super().detach_client(ws_client)

    def forward_from_ws_client(self, ws_client, eth_frame):
        ws_client.pkt_sink.send(eth_frame)

    def _create_pollable(self, ws_client):
        return BridgedTapDevice(self.server, ws_client)

class BridgedTapDevice(Pollable):
    def __init__(self, server, ws_client):
        super().__init__(server)
        self.ws_client = ws_client            ## WebSocketClient, the ws_client associated to this TAP device
        self.out = FrameQueue()               ## frames waiting to be send to the TAP device
        self.br_iface = server.netbe.br_iface ## the bridge's interface name, for example 'wsbr0'
        self.tap_iface = None                 ## string, TAP device name (for example: wstap0)

    def open(self):
        ## open TAP clone device
        self.fd = os.open(TAP_CLONE_DEV, os.O_RDWR | os.O_NONBLOCK)
        super().open(self.fd)
        os.set_blocking(self.fd, False)

        ## create TAP device file, file gets deleted when self.fd is closed
        ifreq = struct.pack('16sH', 'wstap%d'.encode(), IFF_TAP | IFF_NO_PI)
        tunsetiff_result = fcntl.ioctl(self.fd, TUNSETIFF, ifreq)
        self.tap_iface = tunsetiff_result[:16].rstrip(b'\0').decode()

        ## attach TAP device to bridge and bring it up
        run = Exec(logger, check=True)
        #run(f'sysctl net.ipv6.conf.{self.tap_iface}.disable_ipv6=1')
        run(f'ip link set dev {self.tap_iface} master {self.br_iface}')
        #run(f'ip link set dev {self.tap_iface} promisc on')
        run(f'ip link set dev {self.tap_iface} up')

        logger.info(f'created bridged TAP device {self.tap_iface}')

    def close(self):
        fd = self.fd
        super().close()
        if fd is not None:
            os.close(fd)
            logger.info(f'destroyed bridged TAP device {self.tap_iface}')

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
            os.write(self.fd, eth_frame)

    def recv_ready(self):
        self.ws_client.send(os.read(self.fd, 65535))
