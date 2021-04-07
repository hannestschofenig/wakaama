#ifndef OSCORE_H_
#define OSCORE_H_
#include <stdint.h>
#include <time.h>
#include "cose/cose.h"
#include "cn-cbor/cn-cbor.h"
#include "oscore/oscore_config.h"

struct coap_packet_t;

#define OSCORE_PARTIALIV_MAXLEN 5
#define OSCORE_SENDERSEQUENCENUMBER_MAX (uint64_t)((uint64_t)(1) << 40)
#define OSCORE_OPTION_VALUE_MAXLEN 255
#define OSCORE_REPLAY_WINDOW_SIZE 32

// special ptr to serialize empty id in option value
#define OSCORE_EMPTY_ENTRY (void*)0xFF

#define COAP_SERIALIZE_OSCORE_OPTION(number, text)      \
    if (IS_OPTION(coap_pkt, number)) \
    { \
      uint8_t hdr = (coap_pkt->oscore_partialIVLen & 0x07); \
      uint8_t len = hdr + 1; \
      if(coap_pkt->oscore_kidContextLen > 0) { hdr |= 0x10; len+= 1 + coap_pkt->oscore_kidContextLen;}\
      if(coap_pkt->oscore_kid != NULL) hdr |= 0x08; \
      len+=coap_pkt->oscore_kidLen; \
      if(hdr == 0x00){ option += coap_set_option_header(number - current_number, 0, option);} \
      else { \
          option += coap_set_option_header(number - current_number, len, option); \
          *option = hdr; \
          option++; \
          for(size_t i = 0; i < coap_pkt->oscore_partialIVLen; i++) { \
              *option = coap_pkt->oscore_partialIV[i]; \
              option++; \
          } \
          if(coap_pkt->oscore_kidContextLen > 0) { \
              *option = coap_pkt->oscore_kidContextLen; \
              option++; \
          } \
          for(size_t i = 0; i < coap_pkt->oscore_kidContextLen; i++) { \
              *option = coap_pkt->oscore_kidContext[i]; \
              option++; \
          } \
          for(size_t i = 0; i < coap_pkt->oscore_kidLen; i++) { \
              *option = coap_pkt->oscore_kid[i]; \
              option++; \
          } \
      } \
      current_number = number; \
    }


int coap_set_header_oscore(void * packet, uint8_t const * partialIV, uint8_t partialIVLen, uint8_t const * kidcontext, uint8_t kidcontextLen, uint8_t const * kid, uint8_t kidLen);
int coap_get_header_oscore(void * packet, uint8_t const ** partialIV, uint8_t * partialIVLen, uint8_t const ** kidcontext, uint8_t * kidcontextLen, uint8_t const ** kid, uint8_t *kidLen);
int coap_parse_oscore_option(void * packet, uint8_t const * value, uint32_t const optionLength);


typedef int (*oscore_hkdf_extract_func)(uint8_t const * salt, size_t saltLen, uint8_t const * ikm, size_t ikmLen, uint8_t * okm);
typedef int (*oscore_hkdf_expand_func)(uint8_t const * prk, size_t prkLen, uint8_t const * info, size_t infoLen, uint8_t * okm, size_t okmLen);

typedef struct oscore_hkdf_alg {
    struct oscore_hkdf_alg * next;
    cn_cbor id;
    // size of key in bytes
    size_t size;
    oscore_hkdf_extract_func extract;
    oscore_hkdf_expand_func expand;
} oscore_hkdf_alg_t;


typedef struct oscore_common_context {
    // use uint16_t for length to prevent failure
    // common context
    uint8_t const * masterSecret;
    uint16_t masterSecretLen;
    uint8_t const * masterSalt;
    uint16_t masterSaltLen;
    uint8_t const * idContext;
    uint16_t idContextLen;
    cn_cbor hkdfAlgId;
    cn_cbor aeadAlgId;
    
    uint8_t senderId[OSCORE_MAX_ID_LEN];
    uint16_t senderIdLen;
    uint8_t recipientId[OSCORE_MAX_ID_LEN];
    uint16_t recipientIdLen;
    
} oscore_common_context_t;

typedef struct oscore_derived_context {
    // derived context
    // keylen is specified by aeadAlg
    uint8_t senderKey[OSCORE_MAXKEYLEN];
    uint8_t recipientKey[OSCORE_MAXKEYLEN];
    size_t keyLen;
    // nonceLen is specified by aeadAlg
    uint8_t commonIV[OSCORE_MAXNONCELEN];
    size_t nonceLen;
} oscore_derived_context_t;

typedef struct oscore_security_context {
    struct oscore_security_context * next;
    // from common context
    uint8_t const * senderId;
    uint16_t senderIdLen;
    uint8_t const * idContext;
    size_t idContextLen;
    cn_cbor const * aeadAlgId;

    // from derived context
    uint8_t const * senderKey;
    size_t senderKeyLen;
    uint8_t const * commonIV;
    size_t nonceLen;

    // sender part
    uint64_t senderSequenceNumber;

    // replay window
    uint64_t highestValidatedSequenceNumber;
    uint32_t replayWindow;
} oscore_security_context_t;

typedef struct oscore_recipient {
    struct oscore_recipient * next;
    oscore_security_context_t * sender;

    uint8_t const * recipientId;
    uint16_t recipientIdLen;
    
    uint8_t const * recipientKey;
    size_t recipientKeyLen;

} oscore_recipient_t;

typedef struct oscore_request_mapping {
    struct oscore_request_mapping * next;
    oscore_recipient_t * recipient;
    time_t timeout;
    uint8_t token[8];
    uint8_t partialIV[8];
    uint8_t partialIVLen;
    uint8_t tokenLen;
} oscore_request_mapping_t;

typedef struct oscore_context {
    cose_context_t cose;
    oscore_hkdf_alg_t * hkdf;
    // own context
    oscore_security_context_t * security;
    // recipients
    oscore_recipient_t * recipient;
    // requests
    oscore_request_mapping_t * request;
} oscore_context_t;

void oscore_init(oscore_context_t * ctx);
void oscore_free(oscore_context_t * ctx);

#ifdef OSCORE_BACKEND
void oscore_backend_init(oscore_context_t * ctx);
void oscore_backend_free(oscore_context_t * ctx);
#endif


// AAD

// as there are currently no Class I options, this is not supported by current implementation
// algorithms could be an array of valid COSE algorithms identifer or just one algorithm identifier
int oscore_additional_authenticated_data_get_size(cn_cbor const * algorithms, uint8_t const * kid, uint8_t const kidLen, uint8_t const * partialIV, uint8_t const partialIVLen);

// use oscore_additional_authenticated_data_get_size to precalculate size
int oscore_additional_authenticated_data_serialize(uint8_t * buffer, size_t const length, cn_cbor const * algorithms, uint8_t const * kid, uint8_t const kidLen, uint8_t const * partialIV, uint8_t const partialIVLen);


// HKDF

int oscore_hkdf_algorithm_add(oscore_context_t * ctx, oscore_hkdf_alg_t * hkdf);
oscore_hkdf_alg_t * oscore_hkdf_algorithm_find(oscore_context_t * ctx, cn_cbor const * id);
int oscore_hkdf_algorithm_rm(oscore_context_t * ctx, cn_cbor * id, oscore_hkdf_alg_t ** hkdf);


// SECURITY CONTEXT

int oscore_derive_context(oscore_context_t * ctx, oscore_common_context_t const * commonCtx, oscore_derived_context_t * derivedCtx);
// nonce must be a buffer with commonIVLen
int oscore_derive_nonce(uint8_t const * id, size_t idLen, uint8_t const * commonIV, size_t commonIVLen, uint8_t const * partialIV, size_t partialIVLen, uint8_t * nonce);
// populates a security ctx and adds it to the list
int oscore_add_security_ctx(oscore_context_t * ctx, oscore_common_context_t const * commonCtx, oscore_derived_context_t const * derivedCtx, oscore_security_context_t * security);
// populates recipient ctx and adds it to the list
int oscore_add_recipient_ctx(oscore_context_t * ctx, oscore_common_context_t const * commonCtx, oscore_derived_context_t const * derivedCtx, oscore_security_context_t * security, oscore_recipient_t * recipient);

oscore_recipient_t * oscore_find_recipient(oscore_recipient_t * begin, uint8_t const * kid, size_t kidLen, uint8_t const * idContext, size_t idContextLen);

// find a request // todo rename oscore_request_rm (maybe also add as static)
oscore_request_mapping_t * oscore_find_request(oscore_request_mapping_t * begin, uint8_t * token, uint8_t tokenLen);
oscore_request_mapping_t * oscore_remove_request(oscore_request_mapping_t * begin, oscore_request_mapping_t * del);


typedef struct oscore_message {
    uint8_t * buffer;
    size_t length;
    
    oscore_recipient_t * recipient;
    
    uint8_t partialIV[8];
    uint8_t partialIVLen;
    bool generatePartialIV;
} oscore_message_t;

// Message

// keep in mind buffer will be overriden, save it if it must be freed afterwards
// set generatePartialIV flag to true if a new partial IV should be generated for response
// otherwise partialIV of msg is used
// buffer will be allocated with OSCORE_MALLOC!
int oscore_message_encrypt(oscore_context_t * ctx, oscore_message_t * msg);

// checks if a received message is an oscore message
int oscore_is_oscore_message(uint8_t const * buffer, size_t length);
#define OSCORE_DECOMPRESS_FAILED -2
#define OSCORE_COULD_NOT_FIND_RECIPIENT -3
#define OSCORE_VERIFICATION_FAILED -4
#define OSCORE_REPLAY_DETECTED -5
// before calling decrypt function, verify message is a oscore message
// populates recipient and partialIV of msg
// verifies and updates recipient context replay window
// msg->buffer is allocated with OSCORE_MALLOC
// buffer of input must be valid as long as packet must be valid
int oscore_message_decrypt(oscore_context_t * ctx, oscore_message_t * msg);
#endif