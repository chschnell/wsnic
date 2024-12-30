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

import os, logging, struct, fcntl, socket
from subprocess import run

from wsnic import Pollable, FrameQueue
from wsnic.dhcp_srv import DhcpServer

logger = logging.getLogger('tap')

TAP_CLONE_DEVICE = '/dev/net/tun'

TUNSETIFF      = 0x400454ca
SIOCGIFFLAGS   = 0x00008913
SIOCSIFFLAGS   = 0x00008914
SIOCSIFADDR    = 0x00008916
SIOCSIFNETMASK = 0x0000891C

IFF_UP    = 0x1
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

class TapDevice(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.eth_iface = self.config.eth_iface
        self.tap_iface = None       ## string, TAP device name (for example: wsnic0)
        self.dhcp_server = None     ## DhcpServer
        self.out = FrameQueue()     ## frames waiting to be send to tap device

    def open(self):
        ## open TAP clone device
        self.fd = os.open(TAP_CLONE_DEVICE, os.O_RDWR | os.O_NONBLOCK)
        os.set_blocking(self.fd, False)

        ## create TAP device, keep its interface name in self.tap_iface and its file descriptor in self.fd
        ifreq = struct.pack('16sH', 'wsnic%d'.encode(), IFF_TAP | IFF_NO_PI)
        tunsetiff_result = fcntl.ioctl(self.fd, TUNSETIFF, ifreq)
        tap_iface_enc = tunsetiff_result[:16].rstrip(b'\0')
        self.tap_iface = tap_iface_enc.decode()
        logger.info(f'TAP device {self.tap_iface} created, setting IP to {self.config.server_addr}/{self.config.netmask}')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ## bind socket to TAP device
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tap_iface_enc)
            sockfd = sock.fileno()

            ## set TAP device IP address
            ifreq = struct.pack('16sH2s4s8s', tap_iface_enc, socket.AF_INET, b'\x00'*2, socket.inet_aton(self.config.server_addr), b'\x00'*8)
            fcntl.ioctl(sockfd, SIOCSIFADDR, ifreq)

            ## set TAP device netmask
            ifreq = struct.pack('16sH2s4s8s', tap_iface_enc, socket.AF_INET, b'\x00'*2, socket.inet_aton(self.config.netmask), b'\x00'*8) 
            fcntl.ioctl(sockfd, SIOCSIFNETMASK, ifreq)

            ## bring TAP device up
            ifreq = struct.pack('16sh', tap_iface_enc, 0)
            flags = struct.unpack('16sh', fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq))[1]
            ifreq = struct.pack('16sh', tap_iface_enc, flags | IFF_UP)
            fcntl.ioctl(sockfd, SIOCSIFFLAGS, ifreq)
        finally:
            sock.close()

        ## setup NAT rules for TAP device
        self._install_nat(True)

        ## setup DHCP server on TAP device
        self.dhcp_server = DhcpServer(self.server)
        self.dhcp_server.open(self.tap_iface)
        
        super().open(self.fd)

    def close(self):
        if self.dhcp_server:
            self.dhcp_server.close()
            self.dhcp_server = None
        fd = self.fd
        super().close()
        if fd is None:
            return
        os.close(fd)
        self._install_nat(False)
        if self.tap_iface:
            logger.info(f'TAP device {self.tap_iface} closed')
            self.tap_iface = None

    def _install_nat(self, do_install):
        cmd = '-A' if do_install else '-D'
        run(['iptables', cmd, 'POSTROUTING', '-t', 'nat', '-o', self.eth_iface, '-j', 'MASQUERADE'], check=do_install)
        run(['iptables', cmd, 'FORWARD', '-i', self.eth_iface, '-o', self.tap_iface, '-m', 'state',
            '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=do_install)
        run(['iptables', cmd, 'FORWARD', '-i', self.tap_iface, '-o', self.eth_iface, '-j', 'ACCEPT'], check=do_install)

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
        self.server.relay_to_ws_client(os.read(self.fd, 65535))
