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

/**
 * \file Rust application glue layer to use parsers written in the Rust
 * language
 *
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 *
 * This rust implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-rust.h"

#ifdef HAVE_RUSTICATA

static struct rust_config _rcfg = {
	.magic = 0x1234,
	.log = &SCLogMessage,
};

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define RUST_DEFAULT_PORT "443"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define RUST_MIN_FRAME_LEN 3

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert rust any any -> any any (msg:"SURICATA Rust empty message"; \
 *    app-layer-event:rust.empty_message; sid:X; rev:Y;)
 */
enum {
    RUST_DECODER_EVENT_EMPTY_MESSAGE,

    RUST_TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT,
    RUST_TLS_DECODER_EVENT_INVALID_STATE,
    RUST_TLS_DECODER_EVENT_RECORD_INCOMPLETE,
    RUST_TLS_DECODER_EVENT_RECORD_WITH_EXTRA_BYTES,
    RUST_TLS_DECODER_EVENT_RECORD_OVERFLOW,
};

SCEnumCharMap rust_decoder_event_table[] = {
    {"EMPTY_MESSAGE", RUST_DECODER_EVENT_EMPTY_MESSAGE},
    { "OVERFLOW_HEARTBEAT_MESSAGE",  RUST_TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT },
    { "INVALID_STATE",  RUST_TLS_DECODER_EVENT_INVALID_STATE },
    { "RECORD_INCOMPLETE",  RUST_TLS_DECODER_EVENT_RECORD_INCOMPLETE },
    { "RECORD_WITH_EXTRA_BYTES",  RUST_TLS_DECODER_EVENT_RECORD_WITH_EXTRA_BYTES },
    { "RECORD_OVERFLOW",  RUST_TLS_DECODER_EVENT_RECORD_OVERFLOW },

    { NULL, -1 },
};

static RustTransaction *RustTxAlloc(RustState *echo)
{
    RustTransaction *tx = SCCalloc(1, sizeof(RustTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}

static void RustTxFree(void *tx)
{
    RustTransaction *rusttx = tx;

    if (rusttx->request_buffer != NULL) {
        SCFree(rusttx->request_buffer);
    }

    if (rusttx->response_buffer != NULL) {
        SCFree(rusttx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&rusttx->decoder_events);

    SCFree(tx);
}

static void *RustStateAlloc(void)
{
    SCLogNotice("Allocating rust state.");
    RustState *state = SCCalloc(1, sizeof(RustState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    state->tls_state = r_tls_state_new();
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void RustStateFree(void *state)
{
    RustState *rust_state = state;
    RustTransaction *tx;
    SCLogNotice("Freeing rust state.");
    while ((tx = TAILQ_FIRST(&rust_state->tx_list)) != NULL) {
        TAILQ_REMOVE(&rust_state->tx_list, tx, next);
        RustTxFree(tx);
    }
    if (rust_state->tls_state != NULL) {
        r_tls_state_free(rust_state->tls_state);
    }
    SCFree(rust_state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the RustState object.
 * \param tx_id the transaction ID to free.
 */
static void RustStateTxFree(void *state, uint64_t tx_id)
{
    RustState *rust_state = state;
    RustTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &rust_state->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&rust_state->tx_list, tx, next);
        RustTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
}

static int RustStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, rust_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "rust enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *RustGetEvents(void *state, uint64_t tx_id)
{
    RustState *rust_state = state;
    RustTransaction *tx;

    TAILQ_FOREACH(tx, &rust_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int RustHasEvents(void *state)
{
    RustState *rust_state = state;
    return rust_state->events;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_RUST if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto RustProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    if (input_len == 0)
        return ALPROTO_UNKNOWN;

    if (r_tls_probe(input,input_len,offset) != 0) {
        SCLogNotice("Detected as ALPROTO_RUST.");
        return ALPROTO_RUST;
    }

    SCLogNotice("Protocol not detected as ALPROTO_RUST.");
    return ALPROTO_UNKNOWN;
}

static int RustParseToServer(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    RustState *rust_state = state;

    SCLogNotice("Parsing packet to server: len=%"PRIu32, input_len);

    int direction = 0; /* to server */
    int status;
    status = r_tls_parse(direction, input, input_len, rust_state->tls_state);


    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    // Get or allocate a transaction
    RustTransaction *tx = TAILQ_LAST(&rust_state->tx_list,_RustTransaction);
    if (tx != NULL) {
        SCLogNotice("Found transaction");
    } else {
        tx = RustTxAlloc(rust_state);
        if (unlikely(tx == NULL)) {
            SCLogNotice("Failed to allocate new Rust tx.");
            goto end;
        }
        SCLogNotice("Allocated Rust tx %"PRIu64".", tx->tx_id);
    }

    if (R_STATUS_HAS_EVENTS(status)) {
        uint32_t event;
        event = r_tls_get_next_event(rust_state->tls_state);
        if (event != 0xffff) {
            AppLayerDecoderEventsSetEventRaw(&tx->decoder_events, event);
        }
    }


end:
    return 0;
}

static int RustParseToClient(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    RustState *rust_state = state;

    SCLogDebug("Parsing packet to client");

    int direction = 1; /* to client */
    int status;
    status = r_tls_parse(direction, input, input_len, rust_state->tls_state);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    RustTransaction *tx = TAILQ_LAST(&rust_state->tx_list,_RustTransaction);
    if (tx != NULL) {
        SCLogNotice("Found transaction");
    } else {
        SCLogNotice("Failed to find transaction for response on rust state %p.",
            rust_state);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on rust state %p.",
        tx->tx_id, rust_state);

    if (R_STATUS_HAS_EVENTS(status)) {
        uint32_t event;
        event = r_tls_get_next_event(rust_state->tls_state);
        if (event != 0xffff) {
            AppLayerDecoderEventsSetEventRaw(&tx->decoder_events, event);
        }
    }

end:
    return 0;
}

static uint64_t RustGetTxCnt(void *state)
{
    RustState *rust_state = state;
    SCLogNotice("Current tx count is %"PRIu64".", rust_state->transaction_max);
    return rust_state->transaction_max;
}

static void *RustGetTx(void *state, uint64_t tx_id)
{
    RustState *rust_state = state;
    RustTransaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &rust_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

static void RustSetTxLogged(void *state, void *vtx, uint32_t logger)
{
    RustTransaction *tx = (RustTransaction *)vtx;
    tx->logged |= logger;
}

static int RustGetTxLogged(void *state, void *vtx, uint32_t logger)
{
    RustTransaction *tx = (RustTransaction *)vtx;
    if (tx->logged & logger)
        return 1;

    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int RustGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int RustGetStateProgress(void *tx, uint8_t direction)
{
    RustTransaction *rust_state_tx = tx;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", rust_state_tx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && rust_state_tx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For echo, just the existence of the transaction means the
         * request is done. */
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *RustGetTxDetectState(void *vtx)
{
    RustTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int RustSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    RustTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

#endif /* HAVE_RUSTICATA */

void RegisterRustParsers(void)
{
#ifdef HAVE_RUSTICATA
    char *proto_name = "rust";

    _rcfg.log_level = sc_log_global_log_level;
    rusticata_init(&_rcfg);

    /* Check if Rust TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("Rust TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_RUST, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, RUST_DEFAULT_PORT,
                ALPROTO_RUST, 0, RUST_MIN_FRAME_LEN, STREAM_TOSERVER,
                RustProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_RUST, 0, RUST_MIN_FRAME_LEN,
                    RustProbingParser)) {
                SCLogNotice("No Rust app-layer configuration, enabling Rust"
                    " detection TCP detection on port %s.",
                    RUST_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    RUST_DEFAULT_PORT, ALPROTO_RUST, 0,
                    RUST_MIN_FRAME_LEN, STREAM_TOSERVER,
                    RustProbingParser);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for Rust.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogNotice("Registering Rust protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new Rust flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_RUST,
            RustStateAlloc, RustStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_RUST,
            STREAM_TOSERVER, RustParseToServer);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_RUST,
            STREAM_TOCLIENT, RustParseToClient);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_RUST,
            RustStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_RUST,
            RustGetTxLogged, RustSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_RUST,
            RustGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_RUST,
            RustGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_RUST, RustGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_RUST,
            RustGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_RUST,
            RustHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_RUST,
            NULL, RustGetTxDetectState, RustSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_RUST,
            RustStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_RUST,
            RustGetEvents);
    }
    else {
        SCLogNotice("Rust protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_RUST,
        RustParserRegisterTests);
#endif
#endif /* HAVE_RUSTICATA */
}

#ifdef UNITTESTS
#endif

void RustParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
