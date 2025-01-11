##
## websock.py
## WebSocket server classes based on websockets.
##

import logging, socket, time

import struct

from websockets.server import ServerProtocol
from websockets.protocol import State
from websockets.http11 import Request
from websockets.frames import Frame, Opcode

from wsnic import Pollable, FrameQueue

logger = logging.getLogger('websock')

class WebSocketServer(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.addr = f'{self.config.ws_server_addr}:{self.config.ws_server_port}'
        self.ws_clients = set()
        self.sock = None

    def open(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.ws_server_addr, self.config.ws_server_port))
        self.sock.setblocking(0)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.listen(1)
        super().open(self.sock.fileno())
        logger.info(f'{self.addr}: WebSocket server listening')

    def close(self):
        super().close()
        ws_clients = self.ws_clients
        self.ws_clients = set()
        for ws_client in ws_clients:
            ws_client.close()
        if self.sock:
            self.sock.close()
            self.sock = None
            logger.info(f'{self.addr}: WebSocket server closed')

    def recv_ready(self):
        sock, addr = self.sock.accept()
        sock.setblocking(0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ws_client = WebSocketClient(self)
        ws_client.open(sock, addr)
        self.ws_clients.add(ws_client)
        logger.info(f'{self.addr}: accepted TCP connection from {ws_client.addr}')

    def remove_client(self, ws_client):
        self.ws_clients.discard(ws_client)

class WebSocketClient(Pollable):
    def __init__(self, ws_server):
        super().__init__(ws_server.server)
        self.ws_server = ws_server            ## WebSocketServer, the server that created this instance
        self.proto = ServerProtocol()         ## sans-io WebSocket protocol handler
        self.out = FrameQueue()               ## frames waiting to be send to self.sock
        self.last_recv_tm = time.time()       ## most recent time any data was received from self.sock
        self.last_ping_tm = self.last_recv_tm ## most recent time a PING was sent to self.sock
        self.closing = False                  ## True: protocol reported close but data to send still pending
        self.sock = None                      ## TCP/IP socket accepted by WebSocketServer
        self.addr = None                      ## string, remote client address "IP:PORT"
        ## members maintained by NetworkBackend
        self.mac_addr = None                  ## bytes, this client's MAC address
        self.pkt_sink = None                  ## Pollable, this client's separate packet sink
        self._max_frames_queued = 0

    def open(self, sock, addr):
        self.sock = sock
        self.addr = f'{addr[0]}:{addr[1]}'
        super().open(sock.fileno())

    def close(self):
        super().close()
        self.netbe.detach_ws_client(self)
        self.ws_server.remove_client(self)
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            logger.info(f'{self.addr}: WebSocket client disconnected (max. frames queued: {self._max_frames_queued})')

    def send_ready(self):
        try:
            while self.sock and not self.out.is_empty():
                self.sock.send(self.out.get_frame())
        except OSError as e:
            self.close()
            logger.debug(f'{self.addr}: WebSocket client disconnected at send(), reason: {e}')
        else:
            self.wants_send(False)
            if self.closing:
                self.close()

    def recv_ready(self):
        while self.sock:
            try:
                ws_data = self.sock.recv(65535)
            except BlockingIOError:
                break
            except OSError as e:
                logger.debug(f'{self.addr}: WebSocket client disconnected at recv(), reason: {e}')
                self.close()
                break
            if ws_data:
                self.recv(ws_data)
                self.last_recv_tm = time.time()
            else:
                self.proto.receive_eof()
                self._pump()

    def refresh(self, tm_now):
        if tm_now - self.last_recv_tm > 30 and tm_now - self.last_ping_tm > 30:
            self.last_ping_tm = tm_now
            self.proto.send_ping(b'PING')
            self._pump()

    def send(self, eth_frame):
        if self.proto.state == State.OPEN:
            self.proto.send_binary(eth_frame)
            self._pump()
        else:
            logger.warning(f'{self.addr}: dropped frame in send() due to non-OPEN proto state {self.proto.state}')

    def recv(self, ws_data):
        self.proto.receive_data(ws_data)
        self._pump()

        for ev in self.proto.events_received():
            if isinstance(ev, Frame):
                if ev.opcode == Opcode.BINARY:
                    self.netbe.forward_from_ws_client(self, ev.data)
                elif ev.opcode == Opcode.PING:
                    self.proto.send_pong(ev.data)
                elif ev.opcode != Opcode.PONG and ev.opcode != Opcode.CLOSE:
                    logger.warning(f'{self.addr}: received unhandled WebSocket packet: {ev.opcode} {ev}')
            elif isinstance(ev, Request):
                self.proto.send_response(self.proto.accept(ev))
                self.netbe.attach_ws_client(self)
                logger.info(f'{self.addr}: accepted WebSocket client connection')
            else:
                logger.error(f'{self.addr}: received unexpected ws packet: {ev}')
            self._pump()

    def _pump(self):
        ## call this method immediately after any of the receive_*(), send_*(), or fail() methods.
        data_to_send = self.proto.data_to_send()
        if len(data_to_send) > 0:
            was_empty = self.out.is_empty()
            for data in data_to_send:
                if len(data):
                    self.out.append(data)
                    self._max_frames_queued = max(self._max_frames_queued, len(self.out.queue))
                elif self.out.is_empty():
                    self.close()
                    return
                else:
                    self.closing = True
            if was_empty:
                self.wants_send(True)
