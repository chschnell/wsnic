##
## nbe_brtap.py
## Network backend: Network bridge with one Linux TAP device per WebSocket client.
##

import os, logging, struct, fcntl

from wsnic import Pollable, NetworkBackend, FrameQueue, run, mac2str
from wsnic.dhcp import DhcpServer

logger = logging.getLogger('brtap')

TAP_CLONE_DEVICE = '/dev/net/tun'

TUNSETIFF      = 0x400454ca
"""
SIOCGIFFLAGS   = 0x00008913
SIOCSIFFLAGS   = 0x00008914
SIOCSIFADDR    = 0x00008916
SIOCSIFNETMASK = 0x0000891C
"""

IFF_UP    = 0x1
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

class BridgedTapNetworkBackend(NetworkBackend):
    # - maintains one TAP device per ws_clients
    # - needs ws_client MAC for packet filtering -- TODO: does it?
    #
    def __init__(self, server):
        super().__init__(server)
        self.br_iface = 'wsnicbr0'
        self.eth_iface = self.config.eth_iface
        self.dhcp_server = None
        self.is_opened = False
        self.restrict_inbound = False

    def _install_nat_rules(self, do_install):
        cmd = '-A' if do_install else '-D'
        """
        run(['iptables', cmd, 'POSTROUTING', '-t', 'nat', '-s', self.config.bridge_subnet,
            '-o', self.eth_iface, '-j', 'MASQUERADE'], logger, check=do_install)
        """
        run(['iptables', cmd, 'POSTROUTING', '-t', 'nat', '-o', self.eth_iface, '-j', 'MASQUERADE'],
            logger, check=do_install)
        run(['iptables', cmd, 'FORWARD', '-i', self.br_iface, '-o', self.eth_iface, '-j', 'ACCEPT'],
            logger, check=do_install)
        if self.restrict_inbound:
            run(['iptables', cmd, 'FORWARD', '-i', self.eth_iface, '-o', self.br_iface, '-m', 'state',
                '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], logger, check=do_install)
        else:
            run(['iptables', cmd, 'FORWARD', '-i', self.eth_iface, '-o', self.br_iface, '-j', 'ACCEPT'],
                logger, check=do_install)

    def open(self):
        if self.is_opened:
            return
        self.is_opened = True
        ## create bridge
        run(['ip', 'link', 'add', self.br_iface, 'type', 'bridge'], logger, check=True)
        run(['ip', 'addr', 'add', f'{self.config.server_addr}/{self.config.netmask}',
            'dev', self.br_iface], logger, check=True)
        run(['ip', 'link', 'set', self.br_iface, 'up'], logger, check=True)
        ## setup bridge NAT rules
        if os.path.isfile('/proc/sys/net/ipv4/ip_forward'):
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f_out:
                f_out.write('1\n')
        else:
            run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], logger, check=True)
        self._install_nat_rules(True)
        logger.info(f'created TAP bridge {self.br_iface}')
        ## install DHCP server on bridge
        self.dhcp_server = DhcpServer(self.server)
        self.dhcp_server.open(self.br_iface)

    def close(self):
        if not self.is_opened:
            return
        if self.dhcp_server:
            self.dhcp_server.close()
            self.dhcp_server = None
        self._install_nat_rules(False)
        run(['ip', 'link', 'del', self.br_iface], logger)
        logger.info(f'destroyed TAP bridge {self.br_iface}')
        self.is_opened = False

    def attach_client(self, ws_client):
        tap_dev = BridgedTapDevice(self.server, ws_client)
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

class BridgedTapDevice(Pollable):
    def __init__(self, server, ws_client):
        super().__init__(server)
        self.ws_client = ws_client              ## WebSocketClient, the ws_client associated to this TAP device
        self.out = FrameQueue()                 ## frames waiting to be send to the TAP device
        self.br_iface = server.netbe.br_iface   ## the bridge's interface name, for example 'wsnicbr0'
        self.tap_iface = None                   ## string, TAP device name (for example: wsnic0)

    def open(self):
        ## open TAP clone device
        self.fd = os.open(TAP_CLONE_DEVICE, os.O_RDWR | os.O_NONBLOCK)
        super().open(self.fd)
        os.set_blocking(self.fd, False)

        ## create TAP device
        ifreq = struct.pack('16sH', 'wsnic%d'.encode(), IFF_TAP | IFF_NO_PI)
        tunsetiff_result = fcntl.ioctl(self.fd, TUNSETIFF, ifreq)
        self.tap_iface = tunsetiff_result[:16].rstrip(b'\0').decode()

        ## attach TAP device to bridge and bring it up
        run(['ip', 'link', 'set', 'dev', self.tap_iface, 'master', self.br_iface], logger, check=True)
        run(['ip', 'link', 'set', 'dev', self.tap_iface, 'up'], logger, check=True)
        logger.info(f'created TAP device {self.tap_iface}')

    def close(self):
        fd = self.fd
        super().close()
        if fd is not None:
            os.close(fd)
            logger.info(f'destroyed TAP device {self.tap_iface}')

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
            self.out.trim_frame(os.write(self.fd, eth_frame))

    def recv_ready(self):
        self.ws_client.send(os.read(self.fd, 65535))
