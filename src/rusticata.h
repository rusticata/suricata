#ifndef __RUSTICATA_CIPHERSUITE_PARAMS__
#define __RUSTICATA_CIPHERSUITE_PARAMS__

// THIS FILE IS AUTO-GENERATED
// DO NOT EDIT IT


enum TlsCipherKx {
	Kx_Null = 0,
	Kx_Psk = 1,
	Kx_Krb5 = 2,
	Kx_Srp = 3,
	Kx_Rsa = 4,
	Kx_Dh = 5,
	Kx_Dhe = 6,
	Kx_Ecdh = 7,
	Kx_Ecdhe = 8,
};

enum TlsCipherAu {
	Au_Null = 0,
	Au_Psk = 1,
	Au_Krb5 = 2,
	Au_Srp = 3,
	Au_Srp_Dss = 4,
	Au_Srp_Rsa = 5,
	Au_Dss = 6,
	Au_Rsa = 7,
	Au_Dhe = 8,
	Au_Ecdsa = 9,
};

enum TlsCipherEnc {
	Enc_Null = 0,
	Enc_Des = 1,
	Enc_TripleDes = 2,
	Enc_Rc2 = 3,
	Enc_Rc4 = 4,
	Enc_Aria = 5,
	Enc_Idea = 6,
	Enc_Seed = 7,
	Enc_Aes = 8,
	Enc_Camellia = 9,
	Enc_Chacha20_Poly1305 = 10,
};

enum TlsCipherEncMode {
	EncMode_Null = 0,
	EncMode_Cbc = 1,
	EncMode_Ccm = 2,
	EncMode_Gcm = 3,
};

enum TlsCipherMac {
	Mac_Null = 0,
	Mac_HmacMd5 = 1,
	Mac_HmacSha1 = 2,
	Mac_HmacSha256 = 3,
	Mac_HmacSha384 = 4,
	Mac_Aead = 5,
};



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

typedef uint32_t cipher_t;

extern uint32_t r_tls_probe(uint8_t *input, uint32_t input_len, uint32_t *offset);
extern uint32_t r_tls_parse(uint8_t direction, const unsigned char* value, uint32_t len, TlsParserState* state) __attribute__((warn_unused_result));

extern uint32_t r_tls_get_next_event(TlsParserState *state);

/* static methods */
extern uint32_t rusticata_tls_cipher_of_string(const char *s);
extern enum TlsCipherKx rusticata_tls_kx_of_cipher(uint16_t);
extern enum TlsCipherAu rusticata_tls_au_of_cipher(uint16_t);
extern enum TlsCipherEnc rusticata_tls_enc_of_cipher(uint16_t);
extern enum TlsCipherEncMode rusticata_tls_encmode_of_cipher(uint16_t);
extern enum TlsCipherMac rusticata_tls_mac_of_cipher(uint16_t);

/* TlsState methods */
extern uint32_t rusticata_tls_get_cipher(TlsParserState *state);
extern uint32_t rusticata_tls_get_dh_key_bits(TlsParserState *state);

// state functions
extern TlsParserState * r_tls_state_new(void);
extern void r_tls_state_free(TlsParserState *);


#endif // __RUSTICATA_CIPHERSUITE_PARAMS__
