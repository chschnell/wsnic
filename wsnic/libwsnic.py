##
## libwsnic.py
## Interfaces C library lib/libwsnic.so.
##

from ctypes import CDLL, Structure, c_uint8, c_uint32, c_uint64, byref, POINTER

from wsnic import MAX_PAYLOAD_SIZE

libwsnic = CDLL('lib/libwsnic.so')

ws_decode_message = libwsnic.ws_decode_message

## Create ctypes declaration for struct state_s defined in wsmask.c:
##
## typedef struct state_s {
##     uint8_t   decode_state;
##     uint8_t   substate;
##     uint8_t   op_code;
##     uint8_t   fin_flag;
##     uint8_t*  payload_buf;
##     uint64_t  payload_len;
##     uint64_t  payload_cursor;
##     uint8_t   payload_masked;
##     uint8_t   payload_mask[4];
## } * state_p;
##
class state_s(Structure):
    _fields_ = [
        ("decode_state",   c_uint8),
        ("substate",       c_uint8),
        ("op_code",        c_uint8),
        ("fin_flag",       c_uint8),
        ("payload_buf",    POINTER(c_uint8)),
        ("payload_len",    c_uint64),
        ("payload_cursor", c_uint64),
        ("payload_masked", c_uint8),
        ("payload_mask",   c_uint8 * 4)]

c_state_p = POINTER(state_s)
c_payload_buf_t = c_uint8 * MAX_PAYLOAD_SIZE

## Create ctypes declaration for function ws_decode_message() defined in wsmask.c:
##
## uint32_t ws_decode_message(
##     state_p state,
##     const uint8_t* data,
##     const uint32_t data_ofs,
##     const uint32_t data_len
## );
##
ws_decode_message.argtypes = (c_state_p, POINTER(c_uint8), c_uint32, c_uint32)
ws_decode_message.restype = c_uint32

WS_DECODE_DONE = 255

class CWsMessageDecoder:
    def __init__(self, ws_client):
        self.ws_client = ws_client               ## parent WebSocketClient
        self.buffer_pool = ws_client.buffer_pool ## BufferPool, shared pool of buffers
        self.payload_buf = None                  ## buffer of the current message's payload
        self.state = state_s()                   ## decoder state
        self.c_state = byref(self.state)

    def decode(self, data, data_len):
        c_data = (c_uint8 * len(data)).from_buffer(data)
        data_ofs = 0
        while data_ofs < data_len:
            if self.payload_buf is None:
                self.payload_buf = self.buffer_pool.get_buffer()
                self.state.payload_buf = c_payload_buf_t.from_buffer(self.payload_buf)
            data_ofs += ws_decode_message(self.c_state, c_data, data_ofs, data_len)
            if self.state.decode_state == WS_DECODE_DONE:
                if self.state.payload_len and self.state.payload_len <= MAX_PAYLOAD_SIZE:
                    payload_buf = memoryview(self.payload_buf)[ : self.state.payload_len ]
                else:
                    ## decoded message without payload, return unused buffer to pool
                    self.buffer_pool.put_buffer(self.payload_buf)
                    payload_buf = None
                self.payload_buf = None
                self.ws_client.handle_ws_message(self.state.op_code, payload_buf)

    def cleanup(self):
        if self.payload_buf:
            self.buffer_pool.put_buffer(self.payload_buf)
            self.payload_buf = None
