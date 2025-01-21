##
## websocksrv.py
## WebSocket Server class.
##

import logging, socket, time, struct, base64, hashlib

from wsnic import Pollable, FrameQueue, log_eth_frame

logger = logging.getLogger('websock')

STATE_AWAIT_HANDSHAKE = 1
STATE_CONNECTED       = 2
STATE_DISCONECTING    = 3
STATE_DISCONECTED     = 4

WS_MAGIC_UUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

OP_CODE_CONTINUATION = 0x0
OP_CODE_TEXT_MSG     = 0x1
OP_CODE_BINARY_MSG   = 0x2
OP_CODE_CLOSE        = 0x8
OP_CODE_PING         = 0x9
OP_CODE_PONG         = 0xA

FLAG_FIN    = 0x80
FLAG_MASKED = 0x80

class WebSocketClient(Pollable):
    def __init__(self, ws_server):
        super().__init__(ws_server.server)
        self.ws_server = ws_server            ## WebSocketServer, the server that created this instance
        self.out = FrameQueue()               ## frames waiting to be send to self.sock
        self.last_recv_tm = time.time()       ## most recent time any data was received from self.sock
        self.last_ping_tm = self.last_recv_tm ## most recent time a PING was sent to self.sock
        self.closing = False                  ## True: protocol reported close but data to send still pending
        self.sock = None                      ## TCP/IP socket accepted by WebSocketServer
        self.addr = None                      ## string, remote client address "IP:PORT"
        self.state = STATE_AWAIT_HANDSHAKE
        self.hs_request_buffer = bytearray()

        ## message decoder state
        self.sock_recv_buf = bytearray(16384) ## fixed buffer for socket.recv_into()
        self.payload_len = None               ## int, payload length of current message
        self.recv_buffer = None               ## bytearray[payload_len], current payload data
        self.recv_cursor = None               ## int, cursor into recv_buffer[]

        ## members maintained by NetworkBackend (TODO: turn into single opaque member "nbe_data")
        self.mac_addr = None                  ## bytes, this client's MAC address
        self.pkt_sink = None                  ## Pollable, this client's separate packet sink

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
            logger.info(f'{self.addr}: WebSocket client disconnected')

    def send(self, eth_frame):
        if self.sock is not None:
            #log_eth_frame('nbe->ws', eth_frame, logger)
            payload_len = len(eth_frame)
            if payload_len < 126:
                ws_header = struct.pack(f'!BB', OP_CODE_BINARY_MSG | FLAG_FIN, payload_len)
            else:
                ws_header = struct.pack(f'!BBH', OP_CODE_BINARY_MSG | FLAG_FIN, 126, payload_len)
            self.out.append([ws_header, eth_frame])
            self.wants_send(True)

    def send_ready(self):
        if self.sock is None:
            return
        gathered_fragments = []
        while not self.out.is_empty():
            gathered_fragments.extend(self.out.get_frame())
        try:
            self.sock.sendmsg(gathered_fragments)
        except OSError as e:
            self.close()
            logger.debug(f'{self.addr}: WebSocket client disconnected at send(), reason: {e}')
        else:
            self.wants_send(False)
            if self.closing:
                self.close()

    def recv_ready(self):
        sock_recv_buf = self.sock_recv_buf
        while self.sock:
            try:
                sock_recv_len = self.sock.recv_into(sock_recv_buf)
                if sock_recv_len <= 0:
                    break
            except BlockingIOError:
                break
            except OSError as e:
                logger.info(f'{self.addr}: WebSocket client disconnected at recv(), reason: {e}')
                self.close()
                break
            if self.state == STATE_CONNECTED:
                self._handle_websocket_message(sock_recv_buf, sock_recv_len)
            elif self.state == STATE_AWAIT_HANDSHAKE:
                hs_websocket_key = None
                header_length = sock_recv_buf.find(b'\r\n\r\n', 0, sock_recv_len)
                if header_length < 0:
                    self.hs_request_buffer.extend(sock_recv_buf[ : sock_recv_len ])
                elif len(self.hs_request_buffer):
                    header_length += len(self.hs_request_buffer)
                    self.hs_request_buffer.extend(sock_recv_buf[ : sock_recv_len ])
                    hs_websocket_key = self._parse_handshake_request(self.hs_request_buffer, header_length)
                    self.hs_request_buffer.clear()
                else:
                    hs_websocket_key = self._parse_handshake_request(sock_recv_buf, header_length)
                if hs_websocket_key:
                    self._send_handshake_response(hs_websocket_key)
                    self.netbe.attach_ws_client(self)
                    self.state = STATE_CONNECTED
                    logger.info(f'{self.addr}: accepted WebSocket client connection')

    def _parse_handshake_request(self, buffer, length):
        hs_upgrade_websocket = False    ## True if header "Upgrade: websocket\r\n" exists
        hs_websocket_key = None         ## bytes value of header "Sec-WebSocket-Key"

        ## parse HTTP request start line, for example "GET / HTTP/1.1\r\n"
        eol_ofs = buffer.find(b'\r\n', 0, length)
        if eol_ofs < 0:
            logger.debug(f'{self.addr}: request dropped, reason: missing HTTP request start line')
            return None
        start_line_fields = buffer[ : eol_ofs].split(b' ')
        if len(start_line_fields) != 3 or start_line_fields[0].upper() != b'GET':
            logger.debug(f'{self.addr}: request dropped, reason: malformed HTTP request start line')
            return None
        cursor = eol_ofs + 2

        ## parse HTTP request header
        while cursor < length:
            ## parse header name into header_name
            eol_ofs = buffer.find(b'\r\n', cursor, length)
            if eol_ofs < 0:
                eol_ofs = length
            colon_ofs = buffer.find(0x3A, cursor, eol_ofs)    ## 0x3A: ASCII colon ":"
            if colon_ofs < 0:
                logger.debug(f'{self.addr}: request dropped, reason: missing colon in HTTP header line')
                return None
            header_name = buffer[cursor : colon_ofs].lower()
            if header_name in [b'sec-websocket-key', b'upgrade']:
                ## parse header value into header_value
                value_ofs = colon_ofs + 1
                while value_ofs < eol_ofs and buffer[value_ofs] == 0x20:    ## 0x20: ASCII whitespace " "
                    value_ofs += 1
                header_value = buffer[value_ofs : eol_ofs]
                if header_name == b'sec-websocket-key':
                    hs_websocket_key = header_value
                else:
                    hs_upgrade_websocket = b'websocket' in header_value 
            cursor = eol_ofs + 2

        if hs_upgrade_websocket and hs_websocket_key is not None:
            return hs_websocket_key
        else:
            return None

    def _send_handshake_response(self, hs_websocket_key):
        raw_websocket_accept  = hs_websocket_key + WS_MAGIC_UUID
        sha1_websocket_accept = hashlib.sha1(raw_websocket_accept).digest()
        sec_websocket_accept  = base64.b64encode(sha1_websocket_accept)
        response_bytes = b'\r\n'.join([
            b'HTTP/1.1 101 Switching Protocols',
            b'Connection: Upgrade',
            b'Upgrade: websocket',
            b'Sec-WebSocket-Version: 13',
            b'Sec-WebSocket-Accept: ' + sec_websocket_accept,
            b'', b'' ])
        self.out.append([response_bytes])
        self.wants_send(True)

    def _handle_websocket_message(self, ws_msg, ws_msg_len):
        msg_byte = ws_msg[0]
        flag_fin = bool(msg_byte & FLAG_FIN)
        op_code = msg_byte & 0x0F
        msg_byte = ws_msg[1]
        flag_masked = bool(msg_byte & FLAG_MASKED)
        self.payload_len = msg_byte & 0x7F
        cursor = 2
        if self.payload_len > 125:
            if self.payload_len == 126:    ## unsigned short (16 bit)
                self.payload_len = struct.unpack_from('!H', ws_msg, offset=cursor)[0]
                cursor += 2
            else:
                ## length is of type unsigned long long (64 bit)
                self.payload_len = struct.unpack_from('!Q', ws_msg, offset=cursor)[0]
                cursor += 8
        mask_bytes = None
        if flag_masked:
            mask_bytes = ws_msg[ cursor : cursor + 4 ]
            cursor += 4

        self.recv_buffer = bytearray(16384)
        self.recv_cursor = 0

        n_remaining = min(self.payload_len - self.recv_cursor, ws_msg_len - cursor)
        for msg_ofs in range(cursor, cursor + n_remaining):
            unmasked_byte = ws_msg[msg_ofs] ^ mask_bytes[self.recv_cursor % 4]
            self.recv_buffer[self.recv_cursor] = unmasked_byte
            self.recv_cursor += 1

        if self.recv_cursor == self.payload_len:
            if op_code == OP_CODE_BINARY_MSG:
                #log_eth_frame('ws->nbe', self.recv_buffer, logger)
                # TODO: pass self.payload_len to forward_from_ws_client() instead of subarray
                self.netbe.forward_from_ws_client(self, self.recv_buffer[ : self.payload_len ])
            elif op_code == OP_CODE_CLOSE:
                # TODO: WebSocket close handshake
                self.close()
            else:
                logger.info(f'STATE_CONNECTED: fin={flag_fin} op_code={op_code} masked={flag_masked} '
                    f'payload_len={self.payload_len} ws_msg_len={ws_msg_len} cursor={cursor}')
            self.payload_len = None
            self.recv_buffer = None
            self.recv_cursor = None

class WebSocketServer(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.addr = f'{self.config.ws_address}:{self.config.ws_port}'
        self.ws_clients = set()
        self.sock = None

    def open(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.ws_address, self.config.ws_port))
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
            logger.info(f'WebSocket server closed')

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
