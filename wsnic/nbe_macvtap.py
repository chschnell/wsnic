##
## nbe_macvtap.py
## Network backend: One macvtap per WebSocket client.
##

import os, logging, struct

from wsnic import NetworkBackend, Pollable, FrameQueue, Exec, mac2str, log_eth_frame
from wsnic.tuntap import open_tap

logger = logging.getLogger('macvtap')

class MacvtapNetworkBackend(NetworkBackend):
    def __init__(self, server):
        super().__init__(server)
        self.ifnum_counter = 0

    def detach_client(self, ws_client):
        if ws_client.pkt_sink:
            ws_client.pkt_sink.close()
            ws_client.pkt_sink = None
        super().detach_client(ws_client)

    def forward_from_ws_client(self, ws_client, eth_frame):
        if not ws_client.pkt_sink:
            dst_mac, src_mac = struct.unpack_from('6s6s', eth_frame)
            """
            self.set_client_mac(ws_client, src_mac)
            """
            ws_client.mac_addr = src_mac
            logger.info(f'{ws_client.addr} is using MAC address {mac2str(src_mac)}')

            tap_dev = MacvtapDevice(self.server, ws_client, self.ifnum_counter)
            tap_dev.open()
            ws_client.pkt_sink = tap_dev
            self.ifnum_counter += 1

        ws_client.pkt_sink.send(eth_frame)

class MacvtapDevice(Pollable):
    def __init__(self, server, ws_client, ifnum):
        super().__init__(server)
        self.ws_client = ws_client ## WebSocketClient, the ws_client associated to this TAP device
        self.ifnum = ifnum         ## int, unique internal macvtap interface id
        self.out = FrameQueue()    ## frames waiting to be send to the TAP device
        self.macvtap_iface = None  ## string, system-unique network device name

    def open(self):
        self.macvtap_iface = f'wsvtap{self.ifnum}'
        logger.info(f'creating macvtap device {self.macvtap_iface}')

        run = Exec(logger, check=True)
        #run(f'ip link add link {self.config.eth_iface} name {self.macvtap_iface} type macvtap')
        run(f'ip link add link {self.config.eth_iface} name {self.macvtap_iface} type macvtap mode bridge')
        run(f'ip link set dev {self.macvtap_iface} address {mac2str(self.ws_client.mac_addr)}')
        run(f'ip link set dev {self.macvtap_iface} promisc on')
        run(f'ip link set dev {self.macvtap_iface} up')

        tap_clone_dev = None
        with open(f'/sys/class/net/{self.macvtap_iface}/ifindex') as f_in:
            tap_clone_dev = f'/dev/tap{int(f_in.read())}'

        logger.info(f'opening mavtap device {self.macvtap_iface} using TAP clone device {tap_clone_dev}')
        self.fd, tap_iface = open_tap(self.macvtap_iface, tap_clone_dev)
        super().open(self.fd)

    def close(self):
        fd = self.fd
        super().close()
        if fd is not None:
            os.close(fd)
        if self.macvtap_iface is not None:
            Exec(logger)(f'ip link del {self.macvtap_iface}')
            logger.info(f'destroyed mavtap device {self.macvtap_iface}')
            self.macvtap_iface = None

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
            log_eth_frame('ws->tap', eth_frame, logger)
            os.write(self.fd, eth_frame)

    def recv_ready(self):
        eth_frame = os.read(self.fd, 65535)
        log_eth_frame('tap->ws', eth_frame, logger)
        self.ws_client.send(eth_frame)
