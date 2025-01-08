##
## nbe_tapdev.py
## Network backend: Single, multiplexed Linux TAP device.
##

import os, logging, struct

from wsnic import NetworkBackend, Pollable, FrameQueue, Exec, mac2str
from wsnic.tuntap import open_tap

logger = logging.getLogger('tapdev')

class TapDeviceNetworkBackend(NetworkBackend):
    ## - maintains a single, shared TAP file Pollable for all ws_clients
    ## - needs ws_client MAC to forward packets to ws_clients by packet destination MAC address
    ##
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
        ## called internally by TapDevice.recv_ready() when a new eth_frame has arrived.
        ##
        ## Function:
        ## - [ indirectly through: self.server.relay_to_ws_client(os.read(self.fd, 65535)) ]
        ## - extract destination MAC address from eth_frame
        ## - lookup ws_client by MAC
        ##   if exists:
        ##     forward eth_frame to ws_client with ws_client.send(eth_frame)
        ##   else if LSB is set (broadcast or multicast):
        ##     forward eth_frame to all attached ws_clients
        ##
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
        ## called by WebSocketClient.recv() when a new eth_frame has arrived.
        ##
        ## Implementation:
        ## - extract destination and source MAC addresses from eth_frame
        ## - if no MAC has yet been assigned:
        ##     call self.set_client_mac()
        ## - if destination MAC is broad- or multicast:
        ##     forward eth_frame to TAP and all ws_clients except self
        ## - elif destination MAC has known ws_client:
        ##     forward eth_frame to ws_client only
        ## - else:
        ##     forward eth_frame to TAP only
        ##
        if not ws_client in self.ws_clients:
            return
        dst_mac, src_mac = struct.unpack_from('6s6s', eth_frame)
        if not ws_client.mac_addr:
            self.set_client_mac(ws_client, src_mac)
            logger.info(f'{ws_client.addr} is using MAC address {mac2str(src_mac)}')
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
        run = Exec(logger, check=do_install)
        run(f'iptables {cmd} POSTROUTING -t nat -s {self.config.subnet} -o {self.eth_iface} -j MASQUERADE')
        run(f'iptables {cmd} FORWARD -i {self.eth_iface} -o {self.tap_iface} -m state --state RELATED,ESTABLISHED -j ACCEPT')
        run(f'iptables {cmd} FORWARD -i {self.tap_iface} -o {self.eth_iface} -d {self.config.subnet} -j DROP')
        run(f'iptables {cmd} FORWARD -i {self.tap_iface} -o {self.eth_iface} -j ACCEPT')

    def open(self):
        ## create TAP device file, file gets deleted when self.fd is closed
        self.fd, self.tap_iface = open_tap('wstap%d')
        super().open(self.fd)

        ## set TAP device IP address/netmask/MTU and bring it up
        run = Exec(logger, check=True)
        #run(f'sysctl net.ipv6.conf.{self.tap_iface}.disable_ipv6=1')
        run(f'ip addr add dev {self.tap_iface} {self.config.server_addr}/{self.config.netmask} brd +')
        run(f'ip link set dev {self.tap_iface} mtu {self.config.dhcp_mtu}')
        run(f'ip link set dev {self.tap_iface} promisc on')
        run(f'ip link set dev {self.tap_iface} up')

        ## setup NAT rules for TAP device
        self._install_nat_rules(True)

        logger.info(f'created TAP device {self.tap_iface}')

    def close(self):
        fd = self.fd
        super().close()
        if fd is not None:
            os.close(fd)
            self._install_nat_rules(False)
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
            os.write(self.fd, eth_frame)

    def recv_ready(self):
        self.netbe.forward_to_ws_client(os.read(self.fd, 65535))
