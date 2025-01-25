/*
 * wsmask.c
 * WebSocket payload mask/unmak function.
 */
#include <stdint.h>
#include <string.h>

#define MAX_PAYLOAD_SIZE 16384

#define WS_FIN_BIT      0x80
#define WS_MASKED_BIT   0x80
#define WS_OP_CODE_BITS 0x0F
#define WS_PAYLOAD_BITS 0x7F

enum {
    DECODE_START   = 0,
    DECODE_LEN7    = 1,
    DECODE_LEN16   = 2,
    DECODE_LEN64   = 3,
    DECODE_MASK    = 4,
    DECODE_PAYLOAD = 5,
    DECODE_DONE    = 255
};

typedef struct state_s {
    uint8_t   decode_state;
    uint8_t   substate;
    uint8_t   op_code;
    uint8_t   fin_flag;
    uint8_t*  payload_buf;
    uint64_t  payload_len;
    uint64_t  payload_cursor;
    uint8_t   payload_masked;
    uint8_t   payload_mask[4];
} * state_p;

static void set_decode_state(state_p state, uint8_t new_state)
{
    if (new_state == DECODE_MASK && !state->payload_masked) {
        // message has no mask bytes if MASKED flag is not set
        new_state = DECODE_PAYLOAD;
    }
    if (new_state == DECODE_PAYLOAD) {
        if (state->payload_len) {
            state->payload_cursor = 0;
        }
        else {
            new_state = DECODE_DONE;
        }
    }
    state->decode_state = new_state;
    state->substate = 0;
}

static uint32_t decode_header(state_p state, const uint8_t* data, uint32_t data_ofs, const uint32_t data_len)
{
    uint32_t data_cursor = data_ofs;
    while (data_cursor < data_len && state->decode_state != DECODE_PAYLOAD) {
        const uint8_t data_byte = data[data_cursor++];
        switch (state->decode_state) {
            case DECODE_START:
                state->op_code = data_byte & WS_OP_CODE_BITS;
                state->fin_flag = data_byte & WS_FIN_BIT ? 1 : 0;
                set_decode_state(state, DECODE_LEN7);
                break;
            case DECODE_LEN7:
                state->payload_masked = data_byte & WS_MASKED_BIT ? 1 : 0;
                state->payload_len = data_byte & WS_PAYLOAD_BITS;   // payload_len: 0 ... 127
                if (state->payload_len == 0) {
                    set_decode_state(state, DECODE_DONE);
                }
                else if (state->payload_len < 126) {
                    set_decode_state(state, DECODE_MASK);
                }
                else if (state->payload_len == 126) {
                    state->payload_len = 0;
                    set_decode_state(state, DECODE_LEN16);
                }
                else {
                    state->payload_len = 0;
                    set_decode_state(state, DECODE_LEN64);
                }
                break;
            case DECODE_LEN16:
                state->payload_len = state->payload_len << 8 | data_byte;
                if (++state->substate == 2) {
                    set_decode_state(state, DECODE_MASK);
                }
                break;
            case DECODE_LEN64:
                state->payload_len = state->payload_len << 8 | data_byte;
                if (++state->substate == 8) {
                    set_decode_state(state, DECODE_MASK);
                }
                break;
            case DECODE_MASK:
                state->payload_mask[state->substate] = data_byte;
                if (++state->substate == 4) {
                    set_decode_state(state, DECODE_PAYLOAD);
                }
                break;
        }
    }
    return data_cursor - data_ofs;
}

static uint32_t decode_payload(state_p state, const uint8_t* data, const uint32_t data_ofs, const uint32_t data_len)
{
    const uint64_t payload_want = state->payload_len - state->payload_cursor;
    const uint32_t data_avail = data_len - data_ofs;
    const uint32_t n_consumed = payload_want < data_avail ? payload_want : data_avail;

    if (state->payload_len <= MAX_PAYLOAD_SIZE) {
        if (state->payload_masked) {
            const uint8_t* const mask = state->payload_mask;
            const uint8_t* data_p = &data[data_ofs];
            const uint8_t* const data_end_p = &data_p[n_consumed];
            uint8_t* payload_p = &state->payload_buf[state->payload_cursor];
            uint8_t mask_cursor = state->payload_cursor & 3;
            for(; data_p<data_end_p; ++payload_p, ++data_p, ++mask_cursor) {
                *payload_p = *data_p ^ mask[mask_cursor & 3];
            }
        }
        else {
            memcpy(&state->payload_buf[state->payload_cursor], &data[data_ofs], n_consumed);
        }
    }

    state->payload_cursor += n_consumed;
    if (state->payload_cursor == state->payload_len) {
        set_decode_state(state, DECODE_DONE);
    }
    return n_consumed;
}

// Decode zero or one WebSocket message(s).
// Returns the number of bytes decoded from data starting data_ofs.
// If state->decode_state is DECODE_DONE after returning from this function
// then a complete message has been decoded into state.
//
uint32_t ws_decode_message(
    state_p state,
    const uint8_t* data,
    const uint32_t data_ofs,
    const uint32_t data_len)
{
    uint32_t data_cursor = data_ofs;

    if (state->decode_state == DECODE_DONE) {
        set_decode_state(state, DECODE_START);
    }

    if (state->decode_state < DECODE_PAYLOAD) {
        data_cursor += decode_header(state, data, data_cursor, data_len);
    }

    if (state->decode_state == DECODE_PAYLOAD) {
        data_cursor += decode_payload(state, data, data_cursor, data_len);
    }

    return data_cursor - data_ofs;
}
