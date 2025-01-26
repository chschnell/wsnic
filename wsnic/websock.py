##
## websock.py
## WebSocket Server classes.
##

import logging, collections, socket, time, struct, base64, hashlib

from wsnic import Pollable, MAX_PAYLOAD_SIZE
#from wsnic.libwsnic import CWsMessageDecoder

logger = logging.getLogger('websock')

WS_MAGIC_UUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

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

MSG_DECODE_START   = 0
MSG_DECODE_LEN7    = 1
MSG_DECODE_LEN16   = 2
MSG_DECODE_LEN64   = 3
MSG_DECODE_MASK    = 4
MSG_DECODE_PAYLOAD = 5
MSG_DECODE_DONE    = 255

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
            self.request_buffer.extend(data[ : data_len ])
            handshake_key = self._parse_handshake_request(self.request_buffer, len(self.request_buffer))
            self.request_buffer.clear()
        else:
            handshake_key = self._parse_handshake_request(data, header_len)
        if handshake_key:
            raw_websocket_accept  = handshake_key + WS_MAGIC_UUID
            sha1_websocket_accept = hashlib.sha1(raw_websocket_accept).digest()
            sec_websocket_accept  = base64.b64encode(sha1_websocket_accept)
            self.ws_client.handle_ws_handshake(sec_websocket_accept)

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

class WsMessageDecoder:
    def __init__(self, ws_client):
        self.ws_client = ws_client           ## parent WebSocketClient
        self.buffer_pool = ws_client.buffer_pool ## BufferPool, shared pool of buffers
        self.op_code = None                  ## int, one of OP_CODE_*
        self.fin_flag = False                ## bool, True: current message has FIN flag set (TODO)
        self.payload_len = 0                 ## int, payload length of current message
        self.payload_masked = False          ## bool, True: payload is XOR masked with payload_mask
        self.payload_mask = bytearray(4)     ## 32 bit XOR mask
        self.payload_buf = None              ## bytearray[payload_len], current payload buffer
        self.payload_cursor = None           ## int, cursor into payload_buf[]
        self.decode_state = MSG_DECODE_START ## int, one of MSG_DECODE_*
        self.decode_substate = None          ## int, sub-state depending on decode_state

    def decode(self, data, data_len):
        data_ofs = 0
        while data_ofs < data_len:
            if self.decode_state < MSG_DECODE_PAYLOAD:
                data_ofs = self._decode_header(data, data_ofs, data_len)
            if self.decode_state == MSG_DECODE_PAYLOAD:
                data_ofs = self._decode_payload(data, data_ofs, data_len)
            if self.decode_state == MSG_DECODE_DONE:
                self.ws_client.handle_ws_message(self.op_code, self.payload_buf)
                self.payload_buf = None
                self._set_decode_state(MSG_DECODE_START)

    def _set_decode_state(self, new_decode_state):
        if new_decode_state == self.decode_state:
            raise Exception(f'already in decode state {new_decode_state}!')
        if new_decode_state == MSG_DECODE_MASK and not self.payload_masked:
            ## no mask bytes if MASKED flag is not set
            new_decode_state = MSG_DECODE_PAYLOAD
        if new_decode_state == MSG_DECODE_PAYLOAD:
            self.payload_cursor = 0
            if self.payload_len:
                if self.payload_len <= MAX_PAYLOAD_SIZE:
                    ## accept payload
                    self.payload_buf = memoryview(self.buffer_pool.get_buffer())[ : self.payload_len ]
                else:
                    ## drop oversized payload
                    self.payload_buf = None
            else:
                ## empty payload
                new_decode_state = MSG_DECODE_DONE
        self.decode_state = new_decode_state
        self.decode_substate = 0

    def _decode_header(self, data, data_ofs, data_len):
        while data_ofs < data_len and self.decode_state < MSG_DECODE_PAYLOAD:
            data_byte = data[data_ofs]
            data_ofs += 1
            if self.decode_state == MSG_DECODE_START:
                self.op_code = data_byte & WS_OP_CODE_BITS
                self.fin_flag = bool(data_byte & WS_FIN_BIT)
                self._set_decode_state(MSG_DECODE_LEN7)
            elif self.decode_state == MSG_DECODE_LEN7:
                self.payload_masked = bool(data_byte & WS_MASKED_BIT)
                self.payload_len = 0
                payload_len = data_byte & WS_PAYLOAD_BITS   ## payload_len: 0 ... 127
                if payload_len == 0:
                    self._set_decode_state(MSG_DECODE_DONE)
                elif payload_len < 126:
                    self.payload_len = payload_len
                    self._set_decode_state(MSG_DECODE_MASK)
                elif payload_len == 126:
                    self._set_decode_state(MSG_DECODE_LEN16)
                else:
                    self._set_decode_state(MSG_DECODE_LEN64)
            elif self.decode_state == MSG_DECODE_LEN16:
                self.payload_len = self.payload_len << 8 | data_byte
                self.decode_substate += 1
                if self.decode_substate == 2:
                    self._set_decode_state(MSG_DECODE_MASK)
            elif self.decode_state == MSG_DECODE_LEN64:
                self.payload_len = self.payload_len << 8 | data_byte
                self.decode_substate += 1
                if self.decode_substate == 8:
                    self._set_decode_state(MSG_DECODE_MASK)
            elif self.decode_state == MSG_DECODE_MASK:
                self.payload_mask[self.decode_substate] = data_byte
                self.decode_substate += 1
                if self.decode_substate == 4:
                    self._set_decode_state(MSG_DECODE_PAYLOAD)
            else:
                raise Exception(f'unexpected decode_state {self.decode_state} in WebSocket decoder')
        return data_ofs

    def _decode_payload(self, data, data_ofs, data_len):
        n_consumed = min(self.payload_len - self.payload_cursor, data_len - data_ofs)
        if self.payload_buf:
            payload_buf = self.payload_buf
            payload_cursor = self.payload_cursor
            if self.payload_masked:
                payload_mask = self.payload_mask
                for data_cursor in range(data_ofs, data_ofs + n_consumed):
                    payload_buf[payload_cursor] = data[data_cursor] ^ payload_mask[payload_cursor & 3]
                    payload_cursor += 1
            else:
                payload_buf[payload_cursor : payload_cursor + n_consumed] = data[data_ofs : data_ofs + n_consumed]
        self.payload_cursor += n_consumed
        if self.payload_cursor == self.payload_len:
            self._set_decode_state(MSG_DECODE_DONE)
        return data_ofs + n_consumed

class WebSocketClient(Pollable):
    def __init__(self, ws_server):
        super().__init__(ws_server.server)
        self.ws_server = ws_server                 ## WebSocketServer, the server that created this instance
        self.buffer_pool = self.server.buffer_pool ## BufferPool, shared pool of buffers
        self.sock_recv_buf = bytearray(65536)      ## fixed buffer for socket.recv_into()
        self.decoder = WsHandshakeDecoder(self)    ## either WsHandshakeDecoder or WsMessageDecoder
        self.out = collections.deque()             ## bytes, bytearray or memoryview queued for sending to self.sock
        self.closing = False                       ## bool, close connection as soon as self.out is drained
        self.last_recv_tm = time.time()            ## int, most recent time any data was received from self.sock
        self.last_ping_tm = self.last_recv_tm      ## int, most recent time a PING was sent to self.sock
        self.sock = None                           ## socket, TCP client socket accepted by WebSocketServer
        self.addr = None                           ## string, remote client address "IP:PORT"
        self.nbe_data = None                       ## opaque pointer reserved for NetworkBackend

    def _clear_out(self):
        if self.out:
            self.buffer_pool.put_buffers(self.out)
            self.out.clear()

    def open(self, sock, addr):
        self.sock = sock
        self.addr = f'{addr[0]}:{addr[1]}'
        super().open(sock.fileno())

    def close(self, reason='unknown'):
        super().close()
        self.netbe.detach_ws_client(self)
        self.ws_server.remove_client(self)
        if self.sock is not None:
            self._clear_out()
            self.sock.close()
            self.sock = None
            logger.info(f'{self.addr}: connection closed, reason: {reason}')

    def handle_ws_handshake(self, sec_websocket_accept):
        ## called by WsHandshakeDecoder.decode()
        ## send handshake response
        self.out.append(b'\r\n'.join([
            b'HTTP/1.1 101 Switching Protocols',
            b'Connection: Upgrade',
            b'Upgrade: websocket',
            b'Sec-WebSocket-Accept: ' + sec_websocket_accept,
            b'', b'' ]))
        self.wants_send(True)
        ## accept WebSocket connection
        self.decoder = WsMessageDecoder(self)
        #self.decoder = CWsMessageDecoder(self)
        self.netbe.attach_ws_client(self)
        logger.info(f'{self.addr}: accepted WebSocket client connection')

    def handle_ws_message(self, op_code, payload_buf):
        ## called by WsMessageDecoder.decode()
        if op_code == OP_CODE_BIN_MSG:
            if payload_buf is not None:
                self.netbe.forward_from_ws_client(self, payload_buf)
        elif op_code == OP_CODE_CLOSE:
            logger.debug(f'{self.addr}: received CLOSE from WebSocket client, replying with CLOSE before closing')
            self._send_ws_message(OP_CODE_CLOSE, payload_buf)
            self.closing = True
        elif op_code == OP_CODE_PING:
            logger.debug(f'{self.addr}: received PING from WebSocket client, replying with PONG')
            self._send_ws_message(OP_CODE_PONG, payload_buf)
        else:
            if op_code == OP_CODE_PONG:
                logger.debug(f'{self.addr}: received PONG from WebSocket client')
            elif payload_buf:
                logger.warning(f'{self.addr}: unexpected WebSocket message op_code={op_code} len={len(payload_buf)}')
            else:
                logger.warning(f'{self.addr}: unexpected WebSocket message op_code={op_code} len=0')
            self.buffer_pool.put_buffer(payload_buf)

    def _send_ws_message(self, op_code, payload_buf):
        if self.sock is not None:
            payload_len = len(payload_buf) if payload_buf and len(payload_buf) else 0
            if payload_len < 126:
                self.out.append(struct.pack(f'!BB', op_code | WS_FIN_BIT, payload_len))
            elif payload_len < 65536:
                self.out.append(struct.pack(f'!BBH', op_code | WS_FIN_BIT, 126, payload_len))
            else:
                self.out.append(struct.pack(f'!BBQ', op_code | WS_FIN_BIT, 127, payload_len))
            if payload_len:
                self.out.append(payload_buf)
                payload_buf = None
            self.wants_send(True)
        self.buffer_pool.put_buffer(payload_buf)

    def send_frame(self, eth_frame):
        self._send_ws_message(OP_CODE_BIN_MSG, eth_frame)

    def send_ready(self):
        if self.sock is None:
            return
        if self.out:
            try:
                self.sock.sendmsg(self.out)
                self._clear_out()
            except OSError as e:
                self.close(f'error in socket.sendmsg(): {e}')
        self.wants_send(False)
        if self.closing:
            self.close('closed by client')

    def recv_ready(self):
        recv_buf = self.sock_recv_buf
        try:
            while self.sock:
                recv_len = self.sock.recv_into(recv_buf)
                if recv_len > 0:
                    self.decoder.decode(recv_buf, recv_len)
                    self.last_recv_tm = time.time()
                else:
                    if recv_len == 0:
                        self.close(f'received EOF in sock.recv_into()')
                    else:
                        self.close(f'sock.recv_into() returned unexpected result {recv_len}')
                    break
        except BlockingIOError:
            ## no data available to read from self.sock
            pass
        except OSError as e:
            self.close(f'error in socket.recv_into(): {e}')

    def refresh(self, tm_now):
        if tm_now - self.last_recv_tm > 30 and tm_now - self.last_ping_tm > 30:
            self.last_ping_tm = tm_now
            self._send_ws_message(OP_CODE_PING, b'PING')
            logger.debug(f'{self.addr}: sent PING to idle WebSocket client')

class WebSocketServer(Pollable):
    def __init__(self, server):
        super().__init__(server)
        self.addr = f'{self.config.ws_address}:{self.config.ws_port}'
        self.ws_clients = set()
        self.srv_sock = None

    def open(self):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_sock.bind((self.config.ws_address, self.config.ws_port))
        self.srv_sock.setblocking(0)
        self.srv_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.srv_sock.listen(1)
        super().open(self.srv_sock.fileno())
        logger.info(f'{self.addr}: WebSocket server listening')

    def close(self, reason='unknown'):
        super().close()
        ws_clients = self.ws_clients
        self.ws_clients = set()
        for ws_client in ws_clients:
            ws_client.close(reason)
        if self.srv_sock:
            self.srv_sock.close()
            self.srv_sock = None
            logger.info(f'WebSocket server closed, reason: {reason}')

    def recv_ready(self):
        sock, addr = self.srv_sock.accept()
        sock.setblocking(0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ws_client = WebSocketClient(self)
        ws_client.open(sock, addr)
        self.ws_clients.add(ws_client)
        logger.info(f'{self.addr}: accepted TCP connection from {ws_client.addr}')

    def remove_client(self, ws_client):
        self.ws_clients.discard(ws_client)

    def refresh(self, tm_now):
        for ws_client in self.ws_clients:
            ws_client.refresh(tm_now)
