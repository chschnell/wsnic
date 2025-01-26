##
## nbe_brtap.py
## Network backend: Network bridge with one Linux TAP device per WebSocket client.
##
## Links:
## - Tap networking with QEMU
##   https://wiki.archlinux.org/title/QEMU#Tap_networking_with_QEMU

import os, logging, collections

from wsnic import NetworkBackend, Pollable, Exec, mac2str, random_private_mac
from wsnic.dnsmasq import Dnsmasq
from wsnic.tuntap import open_tap

logger = logging.getLogger('brtap')

class BridgedTapNetworkBackend(NetworkBackend):
    def __init__(self, server):
        super().__init__(server)
        self.br_iface = 'wsbr0'
        self.dhcp_server = None
        self.is_opened = False
        self.restrict_inbound = True

    def _install_nat_rules(self, do_install):
        if self.config.inet_iface:
            if do_install:
                logger.info(f'connecting {self.br_iface} to {self.config.inet_iface} using NAT masquerading')
            else:
                logger.info(f'disconnecting {self.br_iface} from {self.config.inet_iface}')
            cmd = '-A' if do_install else '-D'
            run = Exec(logger, check=do_install)
            run(f'iptables {cmd} POSTROUTING -t nat -s {self.config.subnet} -o {self.config.inet_iface} -j MASQUERADE')
            if self.restrict_inbound:
                run(f'iptables {cmd} FORWARD -i {self.config.inet_iface} -o {self.br_iface} -m state --state RELATED,ESTABLISHED -j ACCEPT')
            else:
                run(f'iptables {cmd} FORWARD -i {self.config.inet_iface} -o {self.br_iface} -j ACCEPT')
            run(f'iptables {cmd} FORWARD -i {self.br_iface} -o {self.config.inet_iface} -d {self.config.subnet} -j DROP')
            run(f'iptables {cmd} FORWARD -i {self.br_iface} -o {self.config.inet_iface} -j ACCEPT')

    def open(self):
        if self.is_opened:
            return
        self.is_opened = True
        logger.info(f'creating bridge {self.br_iface}')
        ## create bridge with manually fixed MAC address, see https://superuser.com/a/1725894
        run = Exec(logger, check=True)
        run(f'ip link add dev {self.br_iface} address {mac2str(random_private_mac())} type bridge')
        run(f'ip addr add dev {self.br_iface} {self.config.server_addr}/{self.config.netmask} brd +')
        run(f'ip link set dev {self.br_iface} up')
        ## setup bridge NAT rules
        self._install_nat_rules(True)
        ## install DHCP server on bridge interface
        if not self.config.disable_dhcp:
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
        ## Create a new BridgedTapDevice tap_device and link it and the
        ## given newly accepted WebSocketClient ws_client to each other:
        ## - ws_client.nbe_data points to tap_device
        ## - tap_device.ws_client points to ws_client
        tap_device = BridgedTapDevice(self.server, ws_client)
        tap_device.open()
        ws_client.nbe_data = tap_device

    def detach_ws_client(self, ws_client):
        if ws_client.nbe_data:
            ws_client.nbe_data.close()
            ws_client.nbe_data = None

    def forward_from_ws_client(self, ws_client, eth_frame):
        ws_client.nbe_data.send_frame(eth_frame)

class BridgedTapDevice(Pollable):
    def __init__(self, server, ws_client):
        super().__init__(server)
        self.ws_client = ws_client            ## WebSocketClient, the ws_client associated to this TAP device
        self.buffer_pool = server.buffer_pool ## BufferPool, shared pool of buffers
        self.out = collections.deque()        ## data chunks queued for sending to the TAP device
        self.br_iface = server.netbe.br_iface ## the bridge's interface name, for example 'wsbr0'
        self.tap_fd = None                    ## int, TAP device file descriptor
        self.tap_iface = None                 ## string, TAP device name (for example: wstap0)

    def _clear_out(self):
        if self.out:
            self.buffer_pool.put_buffers(self.out)
            self.out.clear()

    def open(self):
        ## create and open ws_client's TAP device
        self.tap_fd, self.tap_iface = open_tap('wstap%d')
        super().open(self.tap_fd)
        ## attach TAP device to bridge and bring it up
        Exec(logger, check=True)(f'ip link set dev {self.tap_iface} master {self.br_iface} up')
        logger.info(f'created bridged TAP device {self.tap_iface}')

    def close(self, reason=None):
        super().close()
        if self.tap_fd is not None:
            self._clear_out()
            os.close(self.tap_fd)
            self.tap_fd = None
            logger.info(f'destroyed bridged TAP device {self.tap_iface}')

    def recv_ready(self):
        eth_frame = None
        readv_buffers = [None]
        try:
            while self.tap_fd:
                eth_frame = self.buffer_pool.get_buffer()
                readv_buffers[0] = eth_frame
                eth_frame_len = os.readv(self.tap_fd, readv_buffers)
                if eth_frame_len > 0:
                    self.ws_client.send_frame(memoryview(eth_frame)[ : eth_frame_len ])
                    eth_frame = None
                else:
                    logger.warning(f'{self.tap_iface}: os.readv() returned unexpected result {eth_frame_len}')
                    break
        except BlockingIOError:
            ## no data available to read from TAP device
            pass
        finally:
            if eth_frame:
                self.buffer_pool.put_buffer(eth_frame)

    def send_ready(self):
        if self.out:
            os.writev(self.tap_fd, self.out)
            self._clear_out()
        self.wants_send(False)

    def send_frame(self, eth_frame):
        self.out.append(eth_frame)
        self.wants_send(True)
