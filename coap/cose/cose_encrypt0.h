#ifndef COSE_ENCRYPT0_H_
#define COSE_ENCRYPT0_H_

#include "cose/cose.h"
#include "cose/cose_header.h"





typedef struct cose_encrypt0 {
    cose_header_map_t header;
    uint8_t * ciphertext;
    size_t length;
} cose_encrypt0_t;

void cose_encrypt0_init(cose_encrypt0_t * msg);
void cose_encrypt0_free(cose_context_t * ctx, cose_encrypt0_t * msg);
// frees all pointer (except keyptr), make sure they arent needed later and are allocated by ctx!
void cose_aead_parameters_free(cose_context_t * ctx, cose_aead_parameters_t * par);

//retcode < 0: error happened
//outBufSize will be set to required size
cose_error_t cose_encrypt0_encode_additional_data(cose_context_t *ctx, cose_header_map_t * headermap, uint8_t const * external_aad, size_t external_aadsize, uint8_t * outBuf, size_t * outBufSize);

// tries to populate aead parameters:
// finds key according to encoded kid
// finds IV (allocates new buffer for it!) / Partial IV (prepopulate nonce with new allocated buffer of IV, if PartialIV is encoded in header)
// encodes aad
cose_error_t cose_encrypt0_populate_aead_par(cose_context_t *ctx, cose_header_map_t * headermap, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen);

// checks if supplied parameter are valid for encrypting
cose_error_t cose_encrypt0_aead_par_encrypt_valid(cose_aead_parameters_t * par);
// checks if supplied parameter are valid for decrypting
cose_error_t cose_encrypt0_aead_par_decrypt_valid(cose_aead_parameters_t * par);
// checks if supplied parameter are valid for encrypting with supplied algorithm
cose_error_t cose_encrypt0_aead_par_valid_for(cose_aead_parameters_t * par, cose_aead_alg_t * alg);

// if there is not IV specified, function tries to get IV from msg header
// but DONT add IV AND partial IV to message header because thats not allowed according to RFC
// if there is a partial IV in the msg header, it will be used.
//ssize_t cose_encrypt0_encrypt_str(cose_encrypt0_t * msg, cose_aead_parameters_t * par, char const * algo); //currently not implemented because no string algos are defined
cose_error_t cose_encrypt0_encrypt_uint(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, uint64_t algoId);
cose_error_t cose_encrypt0_encrypt_cbor(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, cn_cbor const * algo);
//tries to locate algorithm in header
cose_error_t cose_encrypt0_encrypt(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen);

//key in par par must not be specified if kid is available in header.
//partial IV and IV will be used accordingly (see cose_encrypt0_encrypt note)
cose_error_t cose_encrypt0_decrypt_cbor(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, cn_cbor const * algo);
cose_error_t cose_encrypt0_decrypt_uint(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, uint64_t algo);
//tries to locate algorithm in header
cose_error_t cose_encrypt0_decrypt(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen);

//if out == NULL, size will be set to needed buffersize
cose_error_t cose_encrypt0_serialize(cose_context_t *ctx, cose_encrypt0_t * msg, uint8_t * out, size_t * len);

//msg is only valid until buffer of in is available!
cose_error_t cose_encrypt0_parse(cose_context_t *ctx, cose_encrypt0_t * msg, uint8_t const * in, size_t len);
#endif