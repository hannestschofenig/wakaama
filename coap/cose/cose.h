#ifndef COSE_H_
#define COSE_H_

#include "cn-cbor/cn-cbor.h"

#define COSE_ALGO_HKDF_SHA_256 -10
#define COSE_ALGO_AES_CCM_16_64_128 0x0A

typedef enum {
    COSE_OK = 0,
    COSE_INVALID_PARAM,
    COSE_OUT_OF_MEMORY,
    COSE_AUTH_FAILED,
    COSE_ALREADY_AVAILABLE,
    COSE_CBOR_INVALID_FORMAT,
    COSE_UNDEFINED_CBOR_ERROR,
    COSE_UNDEFINED_ERROR
} cose_error_t;

// representation of a key
typedef struct cose_key {
    uint8_t * key;
    size_t keyLen;
} cose_key_t;

// key which is identified by a kid
typedef struct cose_identifyable_key {
    struct cose_identifyable_key * next;
    uint8_t * kid;
    size_t kidLen;
    cose_key_t keydata;
} cose_identifyable_key_t;

// all parameter needed to perform aead algorithm
typedef struct cose_aead_parameters {
    uint8_t * plaintext;
    size_t plaintextLen;
    cose_key_t key;
    uint8_t * nonce;
    size_t nonceLen;
    uint8_t * aadEncoded;
    size_t aadLen;
} cose_aead_parameters_t;


typedef struct cose_header_map {
    cn_cbor prot;
    cn_cbor unprot;
} cose_header_map_t;

//output will be preallocted
typedef cose_error_t (*cose_aead_encrypt_func)(cose_aead_parameters_t const * par, cose_header_map_t const * header_map, uint8_t * output);
//buffer for plaintext will be preallocated
typedef cose_error_t (*cose_aead_decrypt_func)(cose_aead_parameters_t * par, cose_header_map_t const * header_map, uint8_t const * encryptedBuffer, size_t const length);

typedef struct cose_aead_alg {
    struct cose_aead_alg * next;
    cn_cbor id;        //identifier according to https://www.iana.org/assignments/cose/cose.xhtml
    cose_aead_encrypt_func encrypt;
    cose_aead_decrypt_func decrypt;
    // parameters according to https://tools.ietf.org/html/rfc5116#section-4
    size_t keyLen;          //  length of key in bytes
    size_t nonceMin;        // minimum number of bytes for nonce
    size_t nonceMax;        // maximum number of bytes for nonce
    size_t relatingCipherTextLen; // number of extra bytes of ciphertext
    cose_identifyable_key_t * keys;
} cose_aead_alg_t;

typedef void *(*cose_calloc_func_t)(size_t count, size_t size, void* context);
typedef void (*cose_free_func_t)(void*ptr, void *context);

typedef struct cose_context{
    cose_aead_alg_t * aead;
    cose_calloc_func_t calloc_func;
    cose_free_func_t free_func;
    void * userContext;
} cose_context_t;


// initializes cose context and backend if defined
cose_error_t cose_init(cose_context_t * context, cose_calloc_func_t calloc_func, cose_free_func_t free_func, void * userContext);
cose_error_t cose_initialized(cose_context_t const * context);
void cose_free(cose_context_t * context);

#ifdef COSE_BACKEND
void cose_backend_init(cose_context_t * ctx);
#endif
/*          
    COSE AEAD
*/
void cose_aead_alg_free(cose_context_t * ctx, cose_aead_alg_t * alg);
cose_error_t cose_aead_algorithm_valid(cose_aead_alg_t const * alg);
//alg->next and alg->keys must be NULL otherwise it cant be added
cose_error_t cose_aead_algorithm_add(cose_context_t * context, cose_aead_alg_t * alg);
// find a aead algorithm identified by id
cose_aead_alg_t * cose_aead_algorithm_find(cose_context_t * context, cn_cbor const * id);
// add a key to a aead algorithm identified by id
cose_error_t cose_aead_algorithm_add_key(cose_context_t * context, cn_cbor const * id, cose_identifyable_key_t * key);
// kid must not be unique! There could be multiple keys with same kid
cose_identifyable_key_t * cose_aead_algorithm_find_key_bykid(cose_identifyable_key_t * begin, uint8_t const * kid, size_t kidLen);
bool cose_aead_algorithm_valid_key(cose_aead_alg_t const * alg, cose_identifyable_key_t const * key);

#endif