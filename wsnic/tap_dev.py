##
## tap_dev.py
## Linux TAP device.
##
## Links:
## - https://github.com/rlisagor/pynetlinux/blob/master/pynetlinux/ifconfig.py
## - https://backreference.org/2010/03/26/tuntap-interface-tutorial/index.html
## - https://man7.org/linux/man-pages/man7/netdevice.7.html
## - https://github.com/mirceaulinic/py-dhcp-relay
## - https://gist.github.com/firaxis/0e538c8e5f81eaa55748acc5e679a36e

import os, logging, struct, fcntl
from subprocess import run

from wsnic import Pollable, FrameQueue
from wsnic.dhcp_srv import DhcpServer

logger = logging.getLogger('tap')

TAP_CLONE_DEVICE = '/dev/net/tun'

TUNSETIFF = 0x400454ca

IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

class TapBridge:
    def __init__(self, server, br_iface='wsnicbr0'):
        self.server = server
        self.config = server.config
        self.br_iface = br_iface
        self.eth_iface = self.config.eth_iface
        self.dhcp_server = None
        self.is_opened = False

    def open(self):
        if self.is_opened:
            return
        self.is_opened = True

        ## create bridge
        run(['ip', 'link', 'add', self.br_iface, 'type', 'bridge'], check=True)
        run(['ip', 'addr', 'add', f'{self.config.bridge_addr}/{self.config.netmask}', 'dev', self.br_iface], check=True)
        run(['ip', 'link', 'set', self.br_iface, 'up'], check=True)

        ## setup bridge NAT rules
        if os.path.isfile('/proc/sys/net/ipv4/ip_forward'):
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f_out:
                f_out.write('1\n')
        else:
            run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
        self._install_nat_rules(True)

        logger.info(f'{self.br_iface}: TAP bridge created')

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

        run(['ip', 'link', 'del', self.br_iface])

        logger.info(f'{self.br_iface}: TAP bridge closed')
        self.is_opened = False

    def _install_nat_rules(self, do_install):
        cmd = '-A' if do_install else '-D'
        run(['iptables', cmd, 'POSTROUTING', '-t', 'nat', '-o', self.eth_iface, '-j', 'MASQUERADE'], check=do_install)
        run(['iptables', cmd, 'FORWARD', '-i', self.br_iface, '-o', self.eth_iface, '-j', 'ACCEPT'], check=do_install)
        if self.config.bridge_restrict_inbound:
            run(['iptables', cmd, 'FORWARD', '-i', self.eth_iface, '-o', self.br_iface,
                '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=do_install)
        else:
            run(['iptables', cmd, 'FORWARD', '-i', self.eth_iface, '-o', self.br_iface, '-j', 'ACCEPT'], check=do_install)

class TapDevice(Pollable):
    def __init__(self, server, ws_client):
        super().__init__(server)
        self.ws_client = ws_client
        self.br_iface = server.tap_bridge.br_iface
        self.tap_iface = None       ## string, TAP device name (for example: wsnic0)
        self.out = FrameQueue()     ## frames waiting to be send to tap device

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
        run(['ip', 'link', 'set', 'dev', self.tap_iface, 'master', self.br_iface], check=True)
        run(['ip', 'link', 'set', 'dev', self.tap_iface, 'up'], check=True)
        logger.info(f'{self.tap_iface}: TAP device created')

    def close(self):
        fd = self.fd
        super().close()
        if fd is not None:
            os.close(fd)
            logger.info(f'{self.tap_iface}: TAP device closed')

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
