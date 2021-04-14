#include "cose/cose.h"
#include <assert.h>
#include <string.h>
#include "cose/cose_util.h"
#include "mbedtls/ccm.h"

#ifndef COSE_ALGO_AES_CCM_16_64_128
#define COSE_ALGO_AES_CCM_16_64_128 0x0A
#endif


static cose_error_t mbedtls_aes_ccm_16_64_128_encrypt(cose_aead_parameters_t const * par, cose_header_map_t const * header_map, uint8_t * output) {
    (void)header_map;
    mbedtls_ccm_context ccmCtx;

    mbedtls_ccm_init(&ccmCtx);
    if(mbedtls_ccm_setkey(&ccmCtx, MBEDTLS_CIPHER_ID_AES, par->key.key, par->key.keyLen*8) != 0) {
        return COSE_INVALID_PARAM;
    }

    int ret = mbedtls_ccm_encrypt_and_tag(&ccmCtx, par->plaintextLen, par->nonce, par->nonceLen,
                         par->aadEncoded, par->aadLen,
                         par->plaintext, output,
                         output+par->plaintextLen, 8);

    mbedtls_ccm_free(&ccmCtx);
    if(ret == 0){
        return COSE_OK;
    }
    return COSE_UNDEFINED_ERROR;
}

static cose_error_t mbedtls_aes_ccm_16_64_128_decrypt(cose_aead_parameters_t * par, cose_header_map_t const * header_map, uint8_t const * encryptedBuffer, size_t const length) {
    (void)header_map;
    mbedtls_ccm_context ccmCtx;

    mbedtls_ccm_init(&ccmCtx);
    if(mbedtls_ccm_setkey(&ccmCtx, MBEDTLS_CIPHER_ID_AES, par->key.key, par->key.keyLen*8) != 0) {
        return COSE_INVALID_PARAM;
    }

    int ret = mbedtls_ccm_auth_decrypt(&ccmCtx, length - 8, par->nonce, par->nonceLen,
                         par->aadEncoded, par->aadLen,
                         encryptedBuffer, par->plaintext,
                         encryptedBuffer + length - 8, 8);

    mbedtls_ccm_free(&ccmCtx);
    if(ret == 0){
        return COSE_OK;
    }
    if(ret == MBEDTLS_ERR_CCM_AUTH_FAILED) {
        return COSE_AUTH_FAILED;
    }
    return COSE_UNDEFINED_ERROR;
}

void cose_backend_init(cose_context_t * ctx) {
    cose_aead_alg_t * alg = (cose_aead_alg_t*)COSE_CALLOC(ctx, sizeof(cose_aead_alg_t));
    memset(alg, 0, sizeof(cose_aead_alg_t));
    alg->id.type = CN_CBOR_UINT;
    alg->id.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    alg->encrypt = mbedtls_aes_ccm_16_64_128_encrypt;
    alg->decrypt = mbedtls_aes_ccm_16_64_128_decrypt;
    alg->keyLen = 16;
    alg->nonceMin = 13;
    alg->nonceMax = 13;
    alg->relatingCipherTextLen = 8;
    cose_error_t ret = cose_aead_algorithm_add(ctx, alg);
    assert(ret == COSE_OK && "Could not load backend correctly");
}