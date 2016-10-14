/* Copyright (C) 2016 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef __APP_LAYER_RUST_H__
#define __APP_LAYER_RUST_H__

#include "detect-engine-state.h"

#include "queue.h"

void RegisterRustParsers(void);
void RustParserRegisterTests(void);

#ifdef HAVE_RUSTICATA

#define R_STATUS_EVENTS   0x0100

#define R_STATUS_OK       0x0000
#define R_STATUS_FAIL     0x0001

#define R_STATUS_EV_MASK  0x0f00
#define R_STATUS_MASK     0x00ff

#define R_STATUS_IS_OK(status) ((status & R_STATUS_MASK)==R_STATUS_OK)
#define R_STATUS_HAS_EVENTS(status) ((status & R_STATUS_EV_MASK)==R_STATUS_EVENTS)

struct rust_config {
	uint32_t magic;
	void *log;
	uint32_t log_level;
};

extern int32_t rusticata_init(struct rust_config *);

struct _TlsParserState;
typedef struct _TlsParserState TlsParserState;

extern uint32_t r_tls_probe(uint8_t *input, uint32_t input_len, uint32_t *offset);
extern uint32_t r_tls_parse(uint8_t direction, const unsigned char* value, uint32_t len, TlsParserState* state) __attribute__((warn_unused_result));

extern uint32_t r_tls_get_next_event(TlsParserState *state);

/* static methods */
extern uint32_t rusticata_tls_cipher_of_string(const char *s);

/* TlsState methods */
extern uint32_t rusticata_tls_get_cipher(TlsParserState *state);

// state functions
extern TlsParserState * r_tls_state_new(void);
extern void r_tls_state_free(TlsParserState *);

// test function
extern int rusticata_use_tls_parser_state(TlsParserState *, int32_t value);


typedef struct RustTransaction_ {

    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    /* flags indicating which loggers that have logged */
    uint32_t logged;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    TAILQ_ENTRY(RustTransaction_) next;

} RustTransaction;

typedef struct RustState_ {

    TlsParserState * tls_state;

    TAILQ_HEAD(_RustTransaction, RustTransaction_) tx_list; /**< List of Rust transactions
                                       * associated with this
                                       * state. */

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */

    uint16_t events; /**< Number of application layer events created
                      * for this state. */

} RustState;

#endif /* HAVE_RUSTICATA */

#endif /* __APP_LAYER_RUST_H__ */
