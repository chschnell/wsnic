##
## nbe_tapdev.py
## Network backend: Single, multiplexed Linux TAP device.
##
## Links:
## - https://github.com/rlisagor/pynetlinux/blob/master/pynetlinux/ifconfig.py
## - https://backreference.org/2010/03/26/tuntap-interface-tutorial/index.html
## - https://man7.org/linux/man-pages/man7/netdevice.7.html
## - https://github.com/mirceaulinic/py-dhcp-relay
## - https://gist.github.com/firaxis/0e538c8e5f81eaa55748acc5e679a36e

import os, logging, struct, fcntl, socket

from wsnic import Pollable, NetworkBackend, FrameQueue, run, mac2str

logger = logging.getLogger('tapdev')

TAP_CLONE_DEVICE = '/dev/net/tun'
TUNSETIFF = 0x400454ca

## Socket configuration controls
SIOCGIFFLAGS   = 0x8913 ## get flags
SIOCSIFFLAGS   = 0x8914 ## set flags
SIOCSIFADDR    = 0x8916 ## set interface address
SIOCSIFNETMASK = 0x891C ## set interface network mask
SIOCSIFMTU     = 0x8922 ## set interface MTU

IFF_UP    = 0x1
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

class TapDeviceNetworkBackend(NetworkBackend):
    # - maintains a single, shared TAP file Pollable for all ws_clients
    # - needs ws_client MAC to forward packets to ws_clients by packet destination MAC address
    #
    def __init__(self, server):
        super().__init__(server)
        self.eth_iface = server.config.eth_iface
        self.dhcp_server = None
        self.tap_dev = None

    def open(self):
        self.tap_dev = TapDevice(self.server)
        self.tap_dev.open()
        ## install DHCP server on TAP device interface
        self.dhcp_server = self.server.create_dhcp_server()
        if self.dhcp_server:
            self.dhcp_server.open(self.tap_dev.tap_iface)

    def close(self):
        if self.dhcp_server:
            self.dhcp_server.close()
            self.dhcp_server = None
        if self.tap_dev:
            self.tap_dev.close()
            self.tap_dev = None

    def forward_to_ws_client(self, eth_frame):
        # called internally by TapDevice.recv_ready() when a new eth_frame has arrived.
        #
        # Function:
        # - [ indirectly through: self.server.relay_to_ws_client(os.read(self.fd, 65535)) ]
        # - extract destination MAC address from eth_frame
        # - lookup ws_client by MAC
        #   if exists:
        #     forward eth_frame to ws_client with ws_client.send(eth_frame)
        #   else if LSB is set (broadcast or multicast):
        #     forward eth_frame to all attached ws_clients
        #
        dst_mac = eth_frame[ : 6 ]
        dst_ws_client = self.mac_to_client.get(dst_mac, None)
        if dst_ws_client:
            dst_ws_client.send(eth_frame)
        elif dst_mac[0] & 0x1:
            ## LSB in first octet: 0=UNICAST, 1=MULTICAST (and also BROADCAST with all octets being 0xff)
            for ws_client_i in self.mac_to_client.values():
                ws_client_i.send(eth_frame)
        else:
            logger.debug(f'dropped packet to ws:{mac2str(dst_mac)}')

    def forward_from_ws_client(self, ws_client, eth_frame):
        # called by WebSocketClient.recv() when a new eth_frame has arrived.
        #
        # Implementation:
        # - extract destination and source MAC addresses from eth_frame
        # - if no MAC has yet been assigned:
        #     call self.set_client_mac()
        # - if destination MAC is broad- or multicast:
        #     forward eth_frame to TAP and all ws_clients except self
        # - elif destination MAC has known ws_client:
        #     forward eth_frame to ws_client only
        # - else:
        #     forward eth_frame to TAP only
        #
        if not ws_client in self.ws_clients:
            return
        dst_mac, src_mac = struct.unpack_from('6s6s', eth_frame)
        if not ws_client.mac_addr:
            self.set_client_mac(ws_client, src_mac)
            logger.info(f'{ws_client.addr}: registered MAC address {mac2str(src_mac)}')
        if dst_mac[0] & 0x1:
            for ws_client_i in self.mac_to_client.values():
                if ws_client_i != ws_client:
                    ws_client_i.send(eth_frame)
            self.tap_dev.send(eth_frame)
        else:
            dst_ws_client = self.mac_to_client.get(dst_mac, None)
            if dst_ws_client:
                dst_ws_client.send(eth_frame)
            else:
                self.tap_dev.send(eth_frame)

class TapDevice(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.eth_iface = self.config.eth_iface
        self.tap_iface = None       ## string, TAP device name, for example "wstap0"
        self.out = FrameQueue()     ## frames waiting to be send to tap device

    def _install_nat_rules(self, do_install):
        cmd = '-A' if do_install else '-D'
        run(['iptables', cmd, 'POSTROUTING', '-t', 'nat', '-o', self.eth_iface,
            '-j', 'MASQUERADE'], logger, check=do_install)
        run(['iptables', cmd, 'FORWARD', '-i', self.eth_iface, '-o', self.tap_iface,
            '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], logger, check=do_install)
        run(['iptables', cmd, 'FORWARD', '-i', self.tap_iface, '-o', self.eth_iface,
            '-j', 'ACCEPT'], logger, check=do_install)

    def open(self):
        ## open TAP clone device
        self.fd = os.open(TAP_CLONE_DEVICE, os.O_RDWR | os.O_NONBLOCK)
        os.set_blocking(self.fd, False)

        ## create TAP device, keep its interface name in self.tap_iface and its file descriptor in self.fd
        ifreq = struct.pack('16sH', 'wstap%d'.encode(), IFF_TAP | IFF_NO_PI)
        tunsetiff_result = fcntl.ioctl(self.fd, TUNSETIFF, ifreq)
        tap_iface_enc = tunsetiff_result[:16].rstrip(b'\0')
        self.tap_iface = tap_iface_enc.decode()
        logger.info(f'created TAP device {self.tap_iface}, setting IP to {self.config.server_addr}/{self.config.netmask}')

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

            ## set TAP device MTU
            ifreq = struct.pack('16sH', tap_iface_enc, 1500)
            fcntl.ioctl(sockfd, SIOCSIFMTU, ifreq)

            ## bring TAP device up
            ifreq = struct.pack('16sH', tap_iface_enc, 0)
            flags = struct.unpack('16sH', fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq))[1]
            ifreq = struct.pack('16sH', tap_iface_enc, flags | IFF_UP)
            fcntl.ioctl(sockfd, SIOCSIFFLAGS, ifreq)
        finally:
            sock.close()

        ## setup NAT rules for TAP device
        self._install_nat_rules(True)

        super().open(self.fd)

    def close(self):
        fd = self.fd
        super().close()
        if fd is None:
            return
        os.close(fd)
        self._install_nat_rules(False)
        if self.tap_iface:
            logger.info(f'destroyed TAP device {self.tap_iface}')
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
        self.netbe.forward_to_ws_client(os.read(self.fd, 65535))
