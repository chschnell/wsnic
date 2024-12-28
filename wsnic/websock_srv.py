##
## websock_srv.py
## WebSocket server classes based on websockets.
##

import socket, time
from collections import deque

from websockets.server import ServerProtocol
from websockets.http11 import Request
from websockets.frames import Frame, Opcode

from wsnic import Pollable, FrameQueue, mac2str

class WebSocketServer(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.sock = None
        self.addr = None

    def open(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.ws_server_addr, self.config.ws_server_port))
        self.sock.setblocking(0)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.listen(1)
        self.addr = f'{self.config.ws_server_addr}:{self.config.ws_server_port}'
        super().open(self.sock.fileno())
        print(f'{self.addr}: WebSocket server listening')

    def close(self):
        super().close()
        if self.sock:
            self.sock.close()
            self.sock = None
            print(f'{self.addr}: WebSocket server closed')

    def recv_ready(self):
        sock, addr = self.sock.accept()
        sock.setblocking(0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ws_client = WebSocketClient(self.server)
        ws_client.open(sock, addr)
        print(f'{self.addr}: accepted TCP connection from {ws_client.addr}')

class WebSocketClient(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.proto = ServerProtocol()           ## sans-io WebSocket protocol handler
        self.out = FrameQueue()                 ## frames waiting to be send to self.sock
        self.last_recv_tm = time.time()         ## most recent time any data was received from self.sock
        self.last_ping_tm = self.last_recv_tm   ## most recent time a PING was sent to self.sock
        self.closing = False                    ## True: protocol reported close but data to send still pending
        self.sock = None                        ## TCP/IP socket accepted by WebSocketServer
        self.addr = None                        ## string, source address "IP:PORT"
        self.mac = None                         ## bytes, MAC address

    def open(self, sock, addr):
        self.sock = sock
        self.addr = f'{addr[0]}:{addr[1]}'
        super().open(sock.fileno())

    def close(self):
        super().close()
        if self.mac is not None:
            self.server.dhcp_network.release_address(self.mac)
            self.server.unregister_ws_client(self)
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            print(f'{self.addr}: WebSocket client disconnected')

    def send_ready(self):
        eth_frame = self.out.get_frame()
        if eth_frame is None:
            self.wants_send(False)
            if self.closing:
                self.close()
        else:
            try:
                n_sent = self.sock.send(eth_frame)
                self.out.trim_frame(n_sent)
            except OSError as e:
                self.close()
                print(f'{self.addr}: WebSocket client disconnected at send(), reason: {e}')

    def recv_ready(self):
        try:
            ws_frame = self.sock.recv(65535)
        except OSError as e:
            ws_frame = b''
            print(f'{self.addr}: WebSocket client disconnected at recv(), reason: {e}')
        if ws_frame:
            self.recv(ws_frame)
            self.last_recv_tm = time.time()
        else:
            self.close()

    def refresh(self, tm_now):
        if tm_now - self.last_recv_tm > 30 and tm_now - self.last_ping_tm > 30:
            self.last_ping_tm = tm_now
            self.proto.send_ping(b'PING')
            self._pump()

    def send(self, eth_frame):
        self.proto.send_binary(eth_frame)
        self._pump()

    def recv(self, ws_data):
        if ws_data:
            self.proto.receive_data(ws_data)
        else:
            self.proto.receive_eof()
        self._pump()

        for ev in self.proto.events_received():
            if isinstance(ev, Frame):
                if ev.opcode == Opcode.BINARY:
                    if self.mac is None:
                        src_mac = ev.data[ 6 : 12 ]
                        self.server.register_ws_client(self, src_mac)
                        print(f'{self.addr}: registered MAC address {mac2str(src_mac)}')
                    self.server.tap_dev.send(ev.data)
                elif ev.opcode == Opcode.PING:
                    self.proto.send_pong(ev.data)
                elif ev.opcode != Opcode.PONG and ev.opcode != Opcode.CLOSE:
                    print(f'{self.addr}: received unhandled WebSocket packet: {ev.opcode} {ev}')
            elif isinstance(ev, Request):
                self.proto.send_response(self.proto.accept(ev))
                print(f'{self.addr}: accepted WebSocket client connection')
            else:
                print(f'{self.addr}: *** received unexpected ws packet: {ev}')
            self._pump()

    def _pump(self):
        ## call this method immediately after any of the receive_*(), send_*(), or fail() methods.
        data_to_send = self.proto.data_to_send()
        if len(data_to_send) > 0:
            was_empty = self.out.is_empty()
            for data in data_to_send:
                if len(data):
                    self.out.append(data)
                elif self.out.is_empty():
                    self.close()
                else:
                    self.closing = True
            if was_empty:
                self.wants_send(True)
