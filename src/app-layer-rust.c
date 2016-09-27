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

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define RUST_MIN_FRAME_LEN 1

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
};

SCEnumCharMap rust_decoder_event_table[] = {
    {"EMPTY_MESSAGE", RUST_DECODER_EVENT_EMPTY_MESSAGE},
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
    state->tls_state = rusticata_new_tls_parser_state();
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
        rusticata_free_tls_parser_state(rust_state->tls_state);
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
    RustState *echo = state;
    RustTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
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
    RustState *echo = state;
    return echo->events;
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
    /* Very simple test - if there is input, this is echo. */
    if (input_len >= RUST_MIN_FRAME_LEN) {
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
    void * p;
    p = rusticata_tls_decode(direction, input, input_len, rust_state->tls_state);
    rusticata_use_tls_parser_state(p, 0x1234);

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

    /* Normally you would parse out data here and store it in the
     * transaction object, but as this is echo, we'll just record the
     * request data. */

    /* Also, if this protocol may have a "protocol data unit" span
     * multiple chunks of data, which is always a possibility with
     * TCP, you may need to do some buffering here.
     *
     * For the sake of simplicity, buffering is left out here, but
     * even for an echo protocol we may want to buffer until a new
     * line is seen, assuming its text based.
     */

    /* Allocate a transaction.
     *
     * But note that if a "protocol data unit" is not received in one
     * chunk of data, and the buffering is done on the transaction, we
     * may need to look for the transaction that this newly recieved
     * data belongs to.
     */
    RustTransaction *tx = RustTxAlloc(rust_state);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new Rust tx.");
        goto end;
    }
    SCLogNotice("Allocated Rust tx %"PRIu64".", tx->tx_id);
    
    /* Make a copy of the request. */
    tx->request_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->request_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->request_buffer, input, input_len);
    tx->request_buffer_len = input_len;

    /* Here we check for an empty message and create an app-layer
     * event. */
    if ((input_len == 1 && tx->request_buffer[0] == '\n') ||
        (input_len == 2 && tx->request_buffer[0] == '\r')) {
        SCLogNotice("Creating event for empty message.");
        AppLayerDecoderEventsSetEventRaw(&tx->decoder_events,
            RUST_DECODER_EVENT_EMPTY_MESSAGE);
        rust_state->events++;
    }

end:    
    return 0;
}

static int RustParseToClient(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    RustState *rust_state = state;
    RustTransaction *tx = NULL, *ttx;;

    SCLogNotice("Parsing packet to client");

    int direction = 1; /* to client */
    void * p;
    p = rusticata_tls_decode(direction, input, input_len, rust_state->tls_state);
    rusticata_use_tls_parser_state(p, 0x1234);

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

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * RustState object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &rust_state->tx_list, next) {
        tx = ttx;
    }
    
    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on echo state %p.",
            rust_state);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on echo state %p.",
        tx->tx_id, rust_state);

    /* If the protocol requires multiple chunks of data to complete, you may
     * run into the case where you have existing response data.
     *
     * In this case, we just log that there is existing data and free it. But
     * you might want to realloc the buffer and append the data.
     */
    if (tx->response_buffer != NULL) {
        SCLogNotice("WARNING: Transaction already has response data, "
            "existing data will be overwritten.");
        SCFree(tx->response_buffer);
    }

    /* Make a copy of the response. */
    tx->response_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->response_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->response_buffer, input, input_len);
    tx->response_buffer_len = input_len;

    /* Set the response_done flag for transaction state checking in
     * RustGetStateProgress(). */
    tx->response_done = 1;

end:
    return 0;
}

static uint64_t RustGetTxCnt(void *state)
{
    RustState *echo = state;
    SCLogNotice("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
}

static void *RustGetTx(void *state, uint64_t tx_id)
{
    RustState *echo = state;
    RustTransaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
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
    RustTransaction *echotx = tx;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", echotx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && echotx->response_done) {
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
#if 1
    {
        TlsParserState * p;
        p = rusticata_new_tls_parser_state();
        SCLogInfo("======= p: %p", p);

        rusticata_use_tls_parser_state(p, 0x1234);

        rusticata_free_tls_parser_state(p);
    }
#endif // 1

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
                SCLogNotice("No echo app-layer configuration, enabling echo"
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
