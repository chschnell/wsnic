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

import os, struct, fcntl, socket
from subprocess import run

from wsnic import Pollable, FrameQueue
from wsnic.dhcp_srv import DhcpListener

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
        self.eth_iface = None       ## string, upstream interface name (for example: eth0)
        self.tap_iface = None       ## string, TAP device name (for example: wsnic0)
        self.dhcp_listener = None   ## DhcpListener
        self.out = FrameQueue()     ## frames waiting to be send to tap device

    def open(self, eth_iface, tap_ip, tap_netmask):
        self.eth_iface = eth_iface

        ## open TAP clone device
        self.fd = os.open(TAP_CLONE_DEVICE, os.O_RDWR | os.O_NONBLOCK)
        os.set_blocking(self.fd, False)

        ## create TAP device
        ifreq = struct.pack('16sH', 'wsnic%d'.encode(), IFF_TAP | IFF_NO_PI)
        tunsetiff_result = fcntl.ioctl(self.fd, TUNSETIFF, ifreq)
        tap_iface_enc = tunsetiff_result[ : 16].rstrip(b'\0')
        self.tap_iface = tap_iface_enc.decode()
        print(f'{self.tap_iface}: TAP device created, setting IP to {tap_ip} and netmask to {tap_netmask}')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, tap_iface_enc)
            sockfd = sock.fileno()

            ## set TAP device IP address
            ifreq = struct.pack('16sH2s4s8s', tap_iface_enc, socket.AF_INET, b'\x00'*2, socket.inet_aton(tap_ip), b'\x00'*8)
            fcntl.ioctl(sockfd, SIOCSIFADDR, ifreq)

            ## set TAP device netmask
            ifreq = struct.pack('16sH2s4s8s', tap_iface_enc, socket.AF_INET, b'\x00'*2, socket.inet_aton(tap_netmask), b'\x00'*8) 
            fcntl.ioctl(sockfd, SIOCSIFNETMASK, ifreq)

            ## bring TAP device up
            ifreq = struct.pack('16sh', tap_iface_enc, 0)
            flags = struct.unpack('16sh', fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq))[1]
            ifreq = struct.pack('16sh', tap_iface_enc, flags | IFF_UP)
            fcntl.ioctl(sockfd, SIOCSIFFLAGS, ifreq)
        finally:
            sock.close()

        ## setup NAT rules for TAP device
        run(['iptables', '-A', 'POSTROUTING', '-t', 'nat', '-o', eth_iface, '-j', 'MASQUERADE'], check=True)
        run(['iptables', '-A', 'FORWARD', '-i', eth_iface, '-o', self.tap_iface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)
        run(['iptables', '-A', 'FORWARD', '-i', self.tap_iface, '-o', eth_iface, '-j', 'ACCEPT'], check=True)

        ## setup DHCP listener on TAP device
        self.dhcp_listener = DhcpListener(self.server)
        self.dhcp_listener.open(self.tap_iface)
        
        super().open(self.fd)

    def close(self):
        if self.dhcp_listener:
            self.dhcp_listener.close()
            self.dhcp_listener = None
        fd = self.fd
        super().close()
        if fd is None:
            return
        os.close(fd)
        if self.tap_iface is None:
            return
        run(['iptables', '-D', 'FORWARD', '-i', self.tap_iface, '-o', self.eth_iface, '-j', 'ACCEPT'])
        run(['iptables', '-D', 'FORWARD', '-i', self.eth_iface, '-o', self.tap_iface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
        run(['iptables', '-D', 'POSTROUTING', '-t', 'nat', '-o', self.eth_iface, '-j', 'MASQUERADE'])
        print(f'{self.tap_iface}: TAP device closed')
        self.tap_iface = None

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
