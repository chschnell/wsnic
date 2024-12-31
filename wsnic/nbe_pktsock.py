##
## nbe_pktsock.py
## Network backend: One Linux packet socket per WebSocket client.
##

import os, logging, struct, socket

from wsnic import Pollable, NetworkBackend, FrameQueue, mac2str

logger = logging.getLogger('pktsock')

ETH_P_ALL = 0x0003

class PacketSocketNetworkBackend(NetworkBackend):
    # - maintains one PacketSocket per ws_client
    # - needs ws_client MAC for packet filtering
    #
    def __init__(self, server):
        super().__init__(server)

    def attach_client(self, ws_client):
        pktsock = PacketSocket(self.server, ws_client)
        pktsock.open()
        ws_client.pkt_sink = pktsock
        super().attach_client(ws_client)

    def detach_client(self, ws_client):
        if ws_client.pkt_sink:
            ws_client.pkt_sink.close()
            ws_client.pkt_sink = None
        super().detach_client(ws_client)

    def forward_from_ws_client(self, ws_client, eth_frame):
        ws_client.pkt_sink.send(eth_frame)

class PacketSocket(Pollable):
    def __init__(self, server, ws_client):
        super().__init__(server)
        self.ws_client = ws_client  ## WebSocketClient, the ws_client associated to this packet socket
        self.out = FrameQueue()     ## frames waiting to be send to the packet socket
        self.sock = None            ## packet socket

    def open(self):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((self.config.eth_iface, 0))
        super().open(self.sock.fileno())

    def close(self):
        super().close()
        if self.sock:
            self.sock.close()
            self.sock = None

    def send(self, eth_frame):
        if len(eth_frame):
            was_empty = self.out.is_empty()
            self.out.append(eth_frame)
            if was_empty:
                self.wants_send(True)

    def send_ready(self):
        eth_frame = self.out.get_frame()
        if not eth_frame:
            self.wants_send(False)
        else:
            self.out.trim_frame(self.sock.send(eth_frame))

            dst_mac, src_mac, eth_type, ip_proto = struct.unpack_from('!6s6sH9xB10x', eth_frame)
            logger.info(f'ws->tap {src_mac.hex()}->{dst_mac.hex()} len={len(eth_frame)} eth_type={hex(eth_type)} ip_proto={ip_proto}')

    def recv_ready(self):
        eth_frame = self.sock.recv(65535)
        dst_mac, src_mac, eth_type, ip_proto = struct.unpack_from('!6s6sH9xB10x', eth_frame)
        if (self.ws_client.mac_addr and self.ws_client.mac_addr == dst_mac) or dst_mac[0] & 1:
            self.ws_client.send(eth_frame)
            logger.info(f'tap->ws {src_mac.hex()}->{dst_mac.hex()} len={len(eth_frame)} eth_type={hex(eth_type)} ip_proto={ip_proto}')
        """
        if eth_type != 0x800 or ip_proto != 6 or (tcp_src_port != 22 and tcp_dst_port != 22):
            if eth_type == 0x800 and ip_proto == 6:
                logger.info(f'recv_ready(): {src_mac.hex()}->{dst_mac.hex()} len={len(eth_frame)} eth_type={hex(eth_type)} ip_proto={ip_proto} tcp={tcp_src_port}:{tcp_dst_port}')
            else:
                logger.info(f'recv_ready(): {src_mac.hex()}->{dst_mac.hex()} len={len(eth_frame)} eth_type={hex(eth_type)} ip_proto={ip_proto}')
        """
