##
## nbe_brtap.py
## Network backend: Network bridge with one Linux TAP device per WebSocket client.
##
## Links:
## - Tap networking with QEMU
##   https://wiki.archlinux.org/title/QEMU#Tap_networking_with_QEMU

import os, logging

from wsnic import NetworkBackend, Pollable, FrameQueue, Exec, mac2str, random_private_mac
from wsnic.dnsmasq import Dnsmasq
from wsnic.tuntap import open_tap

logger = logging.getLogger('brtap')

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
        run(f'iptables {cmd} POSTROUTING -t nat -s {self.config.subnet} -o {self.eth_iface} -j MASQUERADE')
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

        ## create bridge with manually fixed MAC address, see https://superuser.com/a/1725894
        run = Exec(logger, check=True)
        run(f'ip link add dev {self.br_iface} address {mac2str(random_private_mac())} type bridge')
        run(f'ip addr add dev {self.br_iface} {self.config.server_addr}/{self.config.netmask} brd +')
        run(f'ip link set dev {self.br_iface} up')

        ## setup bridge NAT rules
        self._install_nat_rules(True)
        logger.info(f'created bridge {self.br_iface}')

        ## install DHCP server on bridge interface
        if self.config.dhcp_service != 'disabled':
            self.dhcp_server = Dnsmasq(self.server)
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

    def attach_ws_client(self, ws_client):
        tap_dev = self._create_pollable(ws_client)
        tap_dev.open()
        ws_client.pkt_sink = tap_dev

    def detach_ws_client(self, ws_client):
        if ws_client.pkt_sink:
            ws_client.pkt_sink.close()
            ws_client.pkt_sink = None

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
        ## create and open ws_client's TAP device
        self.fd, self.tap_iface = open_tap('wstap%d')
        super().open(self.fd)

        ## attach TAP device to bridge and bring it up
        Exec(logger, check=True)(f'ip link set dev {self.tap_iface} master {self.br_iface} up')

        logger.info(f'created bridged TAP device {self.tap_iface}')

    def close(self):
        fd = self.fd
        super().close()
        if fd is not None:
            os.close(fd)
            logger.info(f'destroyed bridged TAP device {self.tap_iface}')

    def recv_ready(self):
        while self.fd:
            try:
                self.ws_client.send(os.read(self.fd, 65535))
            except BlockingIOError:
                break

    def send_ready(self):
        while self.fd and not self.out.is_empty():
            os.write(self.fd, self.out.get_frame())
        self.wants_send(False)

    def send(self, eth_frame):
        if len(eth_frame):
            if self.out.is_empty():
                self.wants_send(True)
            self.out.append(eth_frame)
