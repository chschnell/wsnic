##
## websock.py
## WebSocket Server classes.
##

import logging, collections, socket, time, struct, base64, hashlib

from wsnic import Pollable

logger = logging.getLogger('websock')

class WsHandshakeDecoder:
    def __init__(self, ws_client):
        self.ws_client = ws_client
        self.request_buffer = bytearray()

    def decode(self, data, data_len):
        handshake_key = None
        header_len = data.find(b'\r\n\r\n', 0, data_len)
        if header_len < 0:
            self.request_buffer.extend(data[ : data_len ])
        elif len(self.request_buffer):
            header_len += len(self.request_buffer)
            self.request_buffer.extend(data[ : data_len ])
            handshake_key = self._parse_handshake_request(self.request_buffer, header_len)
            self.request_buffer.clear()
        else:
            handshake_key = self._parse_handshake_request(data, header_len)
        if handshake_key:
            self.ws_client.handle_ws_handshake(handshake_key)

    def _parse_handshake_request(self, data, data_len):
        hs_upgrade_websocket = False    ## True if header "Upgrade: websocket\r\n" exists
        handshake_key = None            ## bytes value of header "Sec-WebSocket-Key"

        ## parse HTTP request start line, for example "GET / HTTP/1.1\r\n"
        eol_ofs = data.find(b'\r\n', 0, data_len)
        if eol_ofs < 0:
            logger.debug(f'{self.addr}: request dropped, reason: missing HTTP request start line')
            return None
        start_line_fields = data[ : eol_ofs].split(b' ')
        if len(start_line_fields) != 3 or start_line_fields[0].upper() != b'GET':
            logger.debug(f'{self.addr}: request dropped, reason: malformed HTTP request start line')
            return None
        cursor = eol_ofs + 2

        ## parse HTTP request header
        while cursor < data_len:
            ## parse header name into header_name
            eol_ofs = data.find(b'\r\n', cursor, data_len)
            if eol_ofs < 0:
                eol_ofs = data_len
            colon_ofs = data.find(0x3A, cursor, eol_ofs)    ## 0x3A: ASCII colon ":"
            if colon_ofs < 0:
                logger.debug(f'{self.addr}: request dropped, reason: missing colon in HTTP header line')
                return None
            header_name = data[cursor : colon_ofs].lower()
            if header_name in [b'sec-websocket-key', b'upgrade']:
                ## parse header value into header_value
                value_ofs = colon_ofs + 1
                while value_ofs < eol_ofs and data[value_ofs] == 0x20:    ## 0x20: ASCII whitespace " "
                    value_ofs += 1
                header_value = data[value_ofs : eol_ofs]
                if header_name == b'sec-websocket-key':
                    handshake_key = header_value
                else:
                    hs_upgrade_websocket = b'websocket' in header_value.lower()
            cursor = eol_ofs + 2

        if hs_upgrade_websocket and handshake_key is not None:
            return handshake_key
        else:
            return None

WS_MAGIC_UUID   = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
WS_FIN_BIT      = 0x80
WS_MASKED_BIT   = 0x80
WS_OP_CODE_BITS = 0x0F
WS_PAYLOAD_BITS = 0x7F

OP_CODE_CONTINUATION = 0x0
OP_CODE_TXT_MSG      = 0x1
OP_CODE_BIN_MSG      = 0x2
OP_CODE_CLOSE        = 0x8
OP_CODE_PING         = 0x9
OP_CODE_PONG         = 0xA

MSG_PARSE_START   = 0
MSG_PARSE_LEN7    = 1
MSG_PARSE_LEN16   = 2
MSG_PARSE_LEN64   = 3
MSG_PARSE_MASK    = 4
MSG_PARSE_PAYLOAD = 5
MSG_PARSE_DONE    = 6

MAX_PAYLOAD_SIZE = 16384

class WsMessageDecoder:
    def __init__(self, ws_client):
        self.ws_client = ws_client         ## parent WebSocketClient
        self.op_code = None                ## int, one of OP_CODE_*
        self.fin_flag = False              ## bool, True: current message has FIN flag set (TODO)
        self.payload_len = 0               ## int, payload length of current message
        self.payload_masked = False        ## bool, True: payload is XOR masked with payload_mask
        self.payload_mask = bytearray(4)   ## 32 bit XOR mask
        self.payload_buf = None            ## bytearray[payload_len], current payload buffer
        self.payload_cursor = None         ## int, cursor into payload_buf[]
        self.parse_state = MSG_PARSE_START ## int, one of MSG_PARSE_*
        self.parse_substate = None         ## int, sub-state depending on parse_state

    def decode(self, data, data_len):
        data_ofs = 0
        while data_ofs < data_len:
            if self.parse_state != MSG_PARSE_PAYLOAD:
                data_ofs = self._parse_header(data, data_ofs, data_len)
            if self.parse_state == MSG_PARSE_PAYLOAD:
                data_ofs = self._parse_payload(data, data_ofs, data_len)
            if self.parse_state == MSG_PARSE_DONE:
                self.ws_client.handle_ws_message(self.op_code, self.payload_buf, self.payload_len)
                self.payload_buf = None
                self._set_parse_state(MSG_PARSE_START)

    def _set_parse_state(self, new_parse_state):
        if new_parse_state == MSG_PARSE_MASK and not self.payload_masked:
            ## skip mask bytes if MASKED flag is not set
            new_parse_state = MSG_PARSE_PAYLOAD
        if new_parse_state == MSG_PARSE_PAYLOAD:
            self.payload_cursor = 0
            if self.payload_len > MAX_PAYLOAD_SIZE:
                ## drop oversized payload
                self.payload_buf = None
            elif self.payload_len > 0:
                self.payload_buf = bytearray(MAX_PAYLOAD_SIZE)
            else:
                ## skip empty payload
                new_parse_state = MSG_PARSE_DONE
        self.parse_state = new_parse_state
        self.parse_substate = 0

    def _parse_header(self, data, data_ofs, data_len):
        while data_ofs < data_len and self.parse_state < MSG_PARSE_PAYLOAD:
            data_byte = data[data_ofs]
            data_ofs += 1
            if self.parse_state == MSG_PARSE_START:
                self.op_code = data_byte & WS_OP_CODE_BITS
                self.fin_flag = bool(data_byte & WS_FIN_BIT)
                self._set_parse_state(MSG_PARSE_LEN7)
            elif self.parse_state == MSG_PARSE_LEN7:
                self.payload_masked = bool(data_byte & WS_MASKED_BIT)
                self.payload_len = 0
                payload_len = data_byte & WS_PAYLOAD_BITS
                if payload_len == 0:
                    self._set_parse_state(MSG_PARSE_DONE)
                elif payload_len < 126:
                    self.payload_len = payload_len
                    self._set_parse_state(MSG_PARSE_MASK)
                elif payload_len == 126:
                    self._set_parse_state(MSG_PARSE_LEN16)
                else:
                    self._set_parse_state(MSG_PARSE_LEN64)
            elif self.parse_state == MSG_PARSE_LEN16 or self.parse_state == MSG_PARSE_LEN64:
                self.payload_len = self.payload_len << 8 | data_byte
                self.parse_substate += 1
                if (self.parse_state == MSG_PARSE_LEN16 and self.parse_substate == 2) or \
                        (self.parse_state == MSG_PARSE_LEN64 and self.parse_substate == 8):
                    self._set_parse_state(MSG_PARSE_MASK)
            elif self.parse_state == MSG_PARSE_MASK:
                self.payload_mask[self.parse_substate] = data_byte
                self.parse_substate += 1
                if self.parse_substate == 4:
                    self._set_parse_state(MSG_PARSE_PAYLOAD)
            else:
                raise Exception(f'unexpected parse_state {self.parse_state} in WebSocket parser')
        return data_ofs

    def _parse_payload(self, data, data_ofs, data_len):
        n_consumed = min(self.payload_len - self.payload_cursor, data_len - data_ofs)
        payload_buf = self.payload_buf
        if payload_buf is not None:
            payload_cursor = self.payload_cursor
            if self.payload_masked:
                payload_mask = self.payload_mask
                for data_cursor in range(data_ofs, data_ofs + n_consumed):
                    unmasked_byte = data[data_cursor] ^ payload_mask[payload_cursor % 4]
                    payload_buf[payload_cursor] = unmasked_byte
                    payload_cursor += 1
            else:
                payload_buf[payload_cursor : payload_cursor + n_consumed] = data[data_ofs : data_ofs + n_consumed]
        self.payload_cursor += n_consumed
        if self.payload_cursor == self.payload_len:
            self._set_parse_state(MSG_PARSE_DONE)
        return data_ofs + n_consumed

class WebSocketClient(Pollable):
    def __init__(self, ws_server):
        super().__init__(ws_server.server)
        self.ws_server = ws_server              ## WebSocketServer, the server that created this instance
        self.sock_recv_buf = bytearray(65536)   ## fixed buffer for socket.recv_into()
        self.decoder = WsHandshakeDecoder(self) ## either WsHandshakeDecoder or WsMessageDecoder
        self.sock = None                        ## socket, TCP client socket accepted by WebSocketServer
        self.addr = None                        ## string, remote client address "IP:PORT"
        self.nbe_data = None                    ## opaque pointer reserved for NetworkBackend
        self.out = collections.deque()          ## data chunks queued for sending to self.sock
        self.last_recv_tm = time.time()         ## int, most recent time any data was received from self.sock
        self.last_ping_tm = self.last_recv_tm   ## int, most recent time a PING was sent to self.sock
        self.closing = False                    ## bool, close connection as soon as self.out is drained

    def open(self, sock, addr):
        self.sock = sock
        self.addr = f'{addr[0]}:{addr[1]}'
        super().open(sock.fileno())

    def close(self, reason='unknown'):
        super().close()
        self.netbe.detach_ws_client(self)
        self.ws_server.remove_client(self)
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            logger.info(f'{self.addr}: connection closed, reason: {reason}')

    def handle_ws_handshake(self, handshake_key):
        ## called by WsHandshakeDecoder.decode()
        ## send handshake response
        raw_websocket_accept  = handshake_key + WS_MAGIC_UUID
        sha1_websocket_accept = hashlib.sha1(raw_websocket_accept).digest()
        sec_websocket_accept  = base64.b64encode(sha1_websocket_accept)
        self.out.append(b'\r\n'.join([
            b'HTTP/1.1 101 Switching Protocols',
            b'Connection: Upgrade',
            b'Upgrade: websocket',
            b'Sec-WebSocket-Accept: ' + sec_websocket_accept,
            b'', b'' ]))
        self.wants_send(True)
        ## accept WebScocket connection
        self.decoder = WsMessageDecoder(self)
        self.netbe.attach_ws_client(self)
        logger.info(f'{self.addr}: accepted WebSocket client connection')

    def handle_ws_message(self, op_code, payload_buf, payload_len):
        ## called by WsMessageDecoder.decode()
        if op_code == OP_CODE_BIN_MSG:
            if payload_buf is not None:
                self.netbe.forward_from_ws_client(self, payload_buf, payload_len)
        elif op_code == OP_CODE_CLOSE:
            logger.debug(f'{self.addr}: received CLOSE from WebSocket client, replying with CLOSE before closing')
            self._send_ws_message(OP_CODE_CLOSE, None, 0)
            self.closing = True
        elif op_code == OP_CODE_PING:
            logger.debug(f'{self.addr}: received PING from WebSocket client, replying with PONG')
            self._send_ws_message(OP_CODE_PONG, payload_buf, payload_len)
        elif op_code == OP_CODE_PONG:
            logger.debug(f'{self.addr}: received PONG from WebSocket client')
        else:
            logger.info(f'{self.addr}: unexpected WebSocket message op_code={op_code} '
                f'len={payload_len} payload={payload_buf[:payload_len]}')

    def _send_ws_message(self, op_code, payload_buf, payload_len):
        if payload_len < 126:
            self.out.append(struct.pack(f'!BB', op_code | WS_FIN_BIT, payload_len))
        else:
            self.out.append(struct.pack(f'!BBH', op_code | WS_FIN_BIT, 126, payload_len))
        if payload_len:
            if payload_len == len(payload_buf):
                self.out.append(payload_buf)
            else:
                self.out.append(payload_buf[ : payload_len ])
        self.wants_send(True)

    def send_frame(self, eth_frame, eth_frame_len):
        if self.sock is not None:
            self._send_ws_message(OP_CODE_BIN_MSG, eth_frame, eth_frame_len)

    def send_ready(self):
        if self.sock is None:
            return
        try:
            self.sock.sendmsg(self.out)
            self.out.clear()
        except OSError as e:
            self.close(f'error in socket.sendmsg(): {e}')
        else:
            self.wants_send(False)
            if self.closing:
                self.close('closed by client')

    def recv_ready(self):
        recv_buf = self.sock_recv_buf
        try:
            while self.sock:
                recv_len = self.sock.recv_into(recv_buf)
                if recv_len <= 0:
                    break
                self.decoder.decode(recv_buf, recv_len)
                self.last_recv_tm = time.time()
        except BlockingIOError:
            pass
        except OSError as e:
            self.close(f'error in socket.recv_into(): {e}')

    def refresh(self, tm_now):
        if tm_now - self.last_recv_tm > 30 and tm_now - self.last_ping_tm > 30:
            self.last_ping_tm = tm_now
            self._send_ws_message(OP_CODE_PING, b'PING', 4)
            logger.debug(f'{self.addr}: sent PING to idle WebSocket client')

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
            ws_client.close('server shutdown')
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
