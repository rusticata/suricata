/* Copyright (C) 2015 Open Information Security Foundation
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
 * \file
 *
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 *
 * Rust application glue layer to use keywords with parsers written in the Rust
 * language.
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "app-layer-rust.h"
#include "detect-rust.h"

#ifndef HAVE_RUSTICATA
void DetectRustRegister(void) {
}
#endif /* HAVE_RUSTICATA */


#ifdef HAVE_RUSTICATA
/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static void DetectRustDataFree (void *);

/* Prototypes of functions registered in DetectRustRegister below */
static int DetectRustMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, Signature *, const SigMatchCtx *);
static int DetectRustSetup (DetectEngineCtx *, Signature *, char *);
static void DetectRustFree (void *);
static void DetectRustRegisterTests (void);

static int DetectRustTlsCipherMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectRustTlsCipherSetup (DetectEngineCtx *, Signature *, char *);
static void DetectRustTlsCiphertRegisterTests(void);

static int DetectRustTlsKxDHBitsMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectRustTlsKxDHBitsSetup (DetectEngineCtx *, Signature *, char *);
static int DetectRustTlsKxECDHBitsMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectRustTlsKxECDHBitsSetup (DetectEngineCtx *, Signature *, char *);

static int DetectRustTlsCipherKxMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectRustTlsCipherKxSetup (DetectEngineCtx *, Signature *, char *);
static void DetectRustTlsCiphertKxRegisterTests(void);

/**
 * \brief Registration function for rust: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectRustRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_RUST].name = "rust";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_RUST].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_RUST].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_RUST].Match = DetectRustMatch;
    /* setup function is called during signature parsing, when the rust
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_RUST].Setup = DetectRustSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_RUST].Free = DetectRustFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_RUST].RegisterTests = DetectRustRegisterTests;

    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].name = "rust.tls.cipher";
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].desc = "match TLS/SSL cipher";
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlssubject";
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].Match = NULL;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].AppLayerMatch = DetectRustTlsCipherMatch;
    //sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].Setup = DetectRustTlsCipherSetup;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].Free  = DetectRustDataFree;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER].RegisterTests = DetectRustTlsCiphertRegisterTests;

    sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].name = "rust.tls.kx_min_dh_bits";
    sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].desc = "match TLS/SSL DH parameters key bits";
    sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlssubject";
    sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].Match = NULL;
    sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].AppLayerMatch = DetectRustTlsKxDHBitsMatch;
    //sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].Setup = DetectRustTlsKxDHBitsSetup;
    sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].Free  = DetectRustDataFree;
    //sigmatch_table[DETECT_AL_RUST_TLS_KX_DH_BITS].RegisterTests = DetectRustTlsKxBitstRegisterTests;

    sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].name = "rust.tls.kx_min_ecdh_bits";
    sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].desc = "match TLS/SSL ECDH parameters key bits";
    sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlssubject";
    sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].Match = NULL;
    sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].AppLayerMatch = DetectRustTlsKxECDHBitsMatch;
    //sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].Setup = DetectRustTlsKxECDHBitsSetup;
    sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].Free  = DetectRustDataFree;
    //sigmatch_table[DETECT_AL_RUST_TLS_KX_ECDH_BITS].RegisterTests = DetectRustTlsKxBitstRegisterTests;

    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].name = "rust.tls.cipher.kx";
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].desc = "match TLS/SSL cipher key exchange method";
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlssubject";
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].Match = NULL;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].AppLayerMatch = DetectRustTlsCipherKxMatch;
    //sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].Setup = DetectRustTlsCipherKxSetup;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].Free  = DetectRustDataFree;
    sigmatch_table[DETECT_AL_RUST_TLS_CIPHER_KX].RegisterTests = DetectRustTlsCiphertKxRegisterTests;


    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

static void DetectRustDataFree(void* ptr)
{
    DetectRustData *data = (DetectRustData *)ptr;
    if (ptr == NULL)
        return;
    SCFree(data);
}

/**
 * \brief This function is used to match RUST rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectRustData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectRustMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectRustData *rustd = (const DetectRustData *) ctx;
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (rustd->arg1 == p->payload[0] &&
            rustd->arg2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief This function is used to parse rust options passed via rust: keyword
 *
 * \param ruststr Pointer to the user provided rust options
 *
 * \retval rustd pointer to DetectRustData on success
 * \retval NULL on failure
 */
static DetectRustData *DetectRustParse (const char *ruststr)
{
    DetectRustData *rustd = NULL;
    char arg1[4] = "";
    char arg2[4] = "";
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study,
                    ruststr, strlen(ruststr),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    res = pcre_copy_substring((char *) ruststr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_copy_substring((char *) ruststr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

    }

    rustd = SCMalloc(sizeof (DetectRustData));
    if (unlikely(rustd == NULL))
        goto error;
    rustd->arg1 = (uint8_t)atoi(arg1);
    rustd->arg2 = (uint8_t)atoi(arg2);

    return rustd;

error:
    if (rustd)
        SCFree(rustd);
    return NULL;
}

/**
 * \brief parse the options from the 'rust' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param ruststr pointer to the user provided rust options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectRustSetup (DetectEngineCtx *de_ctx, Signature *s, char *ruststr)
{
    DetectRustData *rustd = NULL;
    SigMatch *sm = NULL;

    rustd = DetectRustParse(ruststr);
    if (rustd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_RUST;
    sm->ctx = (void *)rustd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (rustd != NULL)
        DetectRustFree(rustd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectRustData
 *
 * \param ptr pointer to DetectRustData
 */
static void DetectRustFree(void *ptr) {
    DetectRustData *rustd = (DetectRustData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(rustd);
}

static int DetectRustTlsCipherMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectRustData *de_data = (DetectRustData *)m->ctx;

    RustState *rust_state = (RustState *)state;
    if (rust_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }
    int ret = 0;

    uint32_t cipher = rusticata_tls_get_cipher(rust_state->tls_state);

    SCLogDebug("**** cipher: 0x%x", cipher);

    if (cipher == de_data->cipher_id)
        ret = 1;

    SCReturnInt(ret);
}

static int DetectRustTlsCipherSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectRustData *data = NULL;
    SigMatch *sm = NULL;
    uint32_t cipher_id;

    cipher_id = rusticata_tls_cipher_of_string(str);
    if (cipher_id == 0) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "invalid TLS cipher name in rule.");
        goto error;
    }

    data = SCMalloc(sizeof(DetectRustData));
    if (unlikely(data == NULL))
        goto error;

    data->cipher_id = cipher_id;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_RUST) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_RUST_TLS_CIPHER;
    sm->ctx = (void *)data;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_RUST;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (data != NULL)
        SCFree(data);
    return -1;
}

static void DetectRustTlsCiphertRegisterTests(void)
{
}

static int DetectRustTlsKxDHBitsSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectRustData *data = NULL;
    SigMatch *sm = NULL;
    long kx_bits;
    char *endptr;

    kx_bits = strtoul(str,&endptr,0);
    if (endptr != NULL && *endptr!='\0') {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "invalid TLS kx_dh_bits value in rule.");
        goto error;
    }

    data = SCMalloc(sizeof(DetectRustData));
    if (unlikely(data == NULL))
        goto error;

    data->kx_dh_bits = kx_bits;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_RUST) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_RUST_TLS_KX_DH_BITS;
    sm->ctx = (void *)data;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_RUST;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (data != NULL)
        SCFree(data);
    return -1;
}

static int DetectRustTlsKxDHBitsMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectRustData *de_data = (DetectRustData *)m->ctx;

    RustState *rust_state = (RustState *)state;
    if (rust_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }
    int ret = 0;

    uint32_t cipher = rusticata_tls_get_cipher(rust_state->tls_state);
    if (cipher == 0)  {
        SCReturnInt(0);
    }

    enum TlsCipherKx kx = rusticata_tls_kx_of_cipher(cipher);
    // ignore match if not DH
    // XXX can we disable the rule ?
    if (!(kx == Kx_Dh || kx == Kx_Dhe)) {
        SCReturnInt(0);
    }

    uint32_t kx_bits = rusticata_tls_get_dh_key_bits(rust_state->tls_state);
    SCLogNotice("**** dh_key_bits: %u", kx_bits);

	if (kx_bits == 0) {
		SCReturnInt(0);
	}

    if (kx_bits <= de_data->kx_dh_bits)
        ret = 1;

    SCReturnInt(ret);
}

static int DetectRustTlsKxECDHBitsSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectRustData *data = NULL;
    SigMatch *sm = NULL;
    long kx_bits;
    char *endptr;

    kx_bits = strtoul(str,&endptr,0);
    if (endptr != NULL && *endptr!='\0') {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "invalid TLS kx_ecdh_bits value in rule.");
        goto error;
    }

    data = SCMalloc(sizeof(DetectRustData));
    if (unlikely(data == NULL))
        goto error;

    data->kx_ecdh_bits = kx_bits;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_RUST) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_RUST_TLS_KX_DH_BITS;
    sm->ctx = (void *)data;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_RUST;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (data != NULL)
        SCFree(data);
    return -1;
}

static int DetectRustTlsKxECDHBitsMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectRustData *de_data = (DetectRustData *)m->ctx;

    RustState *rust_state = (RustState *)state;
    if (rust_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }
    int ret = 0;

    uint32_t cipher = rusticata_tls_get_cipher(rust_state->tls_state);
    if (cipher == 0)  {
        SCReturnInt(0);
    }

    enum TlsCipherKx kx = rusticata_tls_kx_of_cipher(cipher);
    // ignore match if not ECDH
    // XXX can we disable the rule ?
    if (!(kx == Kx_Ecdh || kx == Kx_Ecdhe)) {
        SCReturnInt(0);
    }

    uint32_t kx_bits = rusticata_tls_get_dh_key_bits(rust_state->tls_state);
    SCLogNotice("**** ecdh_key_bits: %u", kx_bits);

	if (kx_bits == 0) {
		SCReturnInt(0);
	}

    if (kx_bits <= de_data->kx_ecdh_bits)
        ret = 1;

    SCReturnInt(ret);
}

static int DetectRustTlsCipherKxMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectRustData *de_data = (DetectRustData *)m->ctx;

    RustState *rust_state = (RustState *)state;
    if (rust_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }
    int ret = 0;

    uint32_t cipher = rusticata_tls_get_cipher(rust_state->tls_state);

    SCLogDebug("**** cipher: 0x%x", cipher);

    enum TlsCipherKx kx = rusticata_tls_kx_of_cipher(cipher);

    SCLogDebug("**** cipher kx: 0x%x", kx);

    if (kx == de_data->kx)
        ret = 1;

    SCReturnInt(ret);
}

static enum TlsCipherKx _tls_cipher_kx_of_string(const char *str)
{
    if (strcasecmp("adh",str)==0 || strcasecmp("dh",str)==0)
        return Kx_Dh;

    if (strcasecmp("dhe",str)==0)
        return Kx_Dhe;

    if (strcasecmp("ecdh",str)==0)
        return Kx_Ecdh;

    if (strcasecmp("ecdhe",str)==0)
        return Kx_Ecdhe;

    if (strcasecmp("rsa",str)==0)
        return Kx_Rsa;

    if (strcasecmp("psk",str)==0)
        return Kx_Psk;

    if (strcasecmp("srp",str)==0)
        return Kx_Srp;

    if (strcasecmp("krb5",str)==0)
        return Kx_Krb5;

    return (enum TlsCipherKx)-1;
}

static int DetectRustTlsCipherKxSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectRustData *data = NULL;
    SigMatch *sm = NULL;
    enum TlsCipherKx kx;

    kx = _tls_cipher_kx_of_string(str);
    if (kx == (enum TlsCipherKx)-1) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "invalid TLS cipher kx name in rule.");
        goto error;
    }

    data = SCMalloc(sizeof(DetectRustData));
    if (unlikely(data == NULL))
        goto error;

    data->kx = kx;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_RUST) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_RUST_TLS_CIPHER_KX;
    sm->ctx = (void *)data;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_RUST;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (data != NULL)
        SCFree(data);
    return -1;
}

static void DetectRustTlsCiphertKxRegisterTests(void)
{
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectRustParseTest01 (void) {
    DetectRustData *rustd = NULL;
    uint8_t res = 0;

    rustd = DetectRustParse("1,10");
    if (rustd != NULL) {
        if (rustd->arg1 == 1 && rustd->arg2 == 10)
            res = 1;

        DetectRustFree(rustd);
    }

    return res;
}

static int DetectRustSignatureTest01 (void) {
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (rust:1,10; sid:1; rev:1;)");
    if (sig == NULL) {
        printf("parsing signature failed: ");
        goto end;
    }

    /* if we get here, all conditions pass */
    res = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return res;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectRust
 */
void DetectRustRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectRustParseTest01", DetectRustParseTest01);
    UtRegisterTest("DetectRustSignatureTest01",
                   DetectRustSignatureTest01);
#endif /* UNITTESTS */
}
#endif /* HAVE_RUSTICATA */
