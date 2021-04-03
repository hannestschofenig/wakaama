#include "cose/cose_encrypt0.h"
#include "cose/cose_util.h"
#include <string.h>


void cose_encrypt0_init(cose_encrypt0_t * msg) {
    if(msg == NULL){
        return;
    }
    memset(msg, 0, sizeof(cose_encrypt0_t));
    cose_header_map_init(&msg->header);
}
void cose_encrypt0_free(cose_context_t * ctx, cose_encrypt0_t * msg) {
    if(ctx == NULL || msg == NULL){
        return;
    }
    cose_header_map_free(ctx, &msg->header);
    if(msg->ciphertext != NULL){
        COSE_FREEF(ctx, msg->ciphertext);
    }
    memset(msg, 0, sizeof(cose_encrypt0_t));
}

void cose_aead_parameters_free(cose_context_t * ctx, cose_aead_parameters_t * par) {
    if(cose_initialized(ctx) != COSE_OK){
        LOG("Could not free parameter with invalid context");
        return;
    }
    if(par == NULL){
        return;
    }
    if(par->aadEncoded != NULL){
        COSE_FREEF(ctx, par->aadEncoded);
    }
    if(par->plaintext != NULL){
        COSE_FREEF(ctx, par->plaintext);
    }
    if(par->nonce != NULL){
        COSE_FREEF(ctx, par->nonce);
    }
    memset(par, 0, sizeof(cose_aead_parameters_t));
}

cose_error_t cose_encrypt0_encode_additional_data(cose_context_t *ctx, cose_header_map_t * headermap, uint8_t const * external_aad, size_t external_aadsize, uint8_t * outBuf, size_t * outBufSize) {
    if(cose_initialized(ctx) != COSE_OK || !cose_header_map_valid(headermap)){
        LOG("Cant encode if context or headermap invalid");
        return COSE_INVALID_PARAM;
    }
    if(outBufSize == NULL){
        LOG("Cant set serialized size");
        return COSE_INVALID_PARAM;
    }
    CBOR_CONTEXT_INIT(ctx)

    cn_cbor * encStructure = cn_cbor_array_create(CBOR_CONTEXT_INSERT, NULL);
    if(encStructure == NULL){
        return COSE_OUT_OF_MEMORY;
    }
    cn_cbor * str = cn_cbor_string_create("Encrypt0", CBOR_CONTEXT_INSERT, NULL);
    if(str == NULL){
        cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
        return COSE_OUT_OF_MEMORY;
    }
    
    if(!cn_cbor_array_append(encStructure, str, NULL)) {
        cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
        return COSE_UNDEFINED_CBOR_ERROR;
    }

    cn_cbor * protected = NULL;

    if(headermap->prot.first_child == NULL) { // we encode it as 0 bytes
        protected = cn_cbor_data_create(NULL, 0, CBOR_CONTEXT_INSERT, NULL);
    }
    else {
        ssize_t sz = cn_cbor_encoder_write(NULL, 0, 0, &headermap->prot);
        if(sz <= 0) {
            LOG("Could not serialize protected bucket");
            cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
            return COSE_UNDEFINED_CBOR_ERROR;
        }
        uint8_t * serialized = COSE_CALLOC(ctx, sz);
        if(serialized == NULL) {
            cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
            return COSE_OUT_OF_MEMORY;
        }
        ssize_t newSz = cn_cbor_encoder_write(serialized, 0, sz, &headermap->prot);
        // cbor bytestring should free its string -> data_create2 with no flags
        protected = cn_cbor_data_create2(serialized, newSz, 0, CBOR_CONTEXT_INSERT, NULL);
        if(protected == NULL) {
            COSE_FREEF(ctx, serialized);
        }
    }

    if(protected == NULL){
        cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
        return COSE_OUT_OF_MEMORY;
    }

    if(!cn_cbor_array_append(encStructure, protected, NULL)) {
        cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
        cn_cbor_free(protected, CBOR_CONTEXT_INSERT);
        return COSE_UNDEFINED_CBOR_ERROR;
    }

    cn_cbor * extAad = cn_cbor_data_create(external_aad, external_aadsize, CBOR_CONTEXT_INSERT, NULL);
    if(extAad == NULL){
        cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
        return COSE_OUT_OF_MEMORY;
    }
    if(!cn_cbor_array_append(encStructure, extAad, NULL)) {
        cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
        cn_cbor_free(extAad, CBOR_CONTEXT_INSERT);
        return COSE_UNDEFINED_CBOR_ERROR;
    }

    ssize_t ret = cn_cbor_encoder_write(outBuf, 0, *outBufSize, encStructure);
    cn_cbor_free(encStructure, CBOR_CONTEXT_INSERT);
    if(ret <= 0){
        LOG("Write of encoded additional authenticated data was not possible");
        return COSE_UNDEFINED_CBOR_ERROR;
    }
    *outBufSize = ret;
    return COSE_OK;
}


cose_error_t cose_encrypt0_populate_aead_par(cose_context_t *ctx, cose_header_map_t * headermap, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen) {
    if(cose_initialized(ctx) != COSE_OK){
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_valid(headermap)){
        return COSE_INVALID_PARAM;
    }
    if(par == NULL){
        return COSE_INVALID_PARAM;
    }
    cn_cbor label;
    memset(&label, 0, sizeof(cn_cbor));
    if(par->nonce == NULL){
        
        cn_cbor * iv = cose_header_map_find_uint(headermap, COSE_HEADER_LABEL_IV);
        if(iv != NULL && iv->length > 0){
            par->nonce = COSE_CALLOC(ctx, iv->length);
            if(par->nonce != NULL){
                memcpy(par->nonce, iv->v.bytes, iv->length);
                par->nonceLen = iv->length;
            }
            
        }
    }
    if(par->nonce != NULL) {
        cn_cbor * partialIV = cose_header_map_find_uint(headermap, COSE_HEADER_LABEL_PARTIAL_IV);
        if(partialIV != NULL && partialIV->length < par->nonceLen){
            for(size_t i = 0; i < partialIV->length; i++){
                par->nonce[par->nonceLen-i-1] = par->nonce[par->nonceLen-i-1] ^ partialIV->v.bytes[partialIV->length-i-1];
            }
        }
    }

    if(par->aadEncoded == NULL){
        size_t sz = 0;
        if(cose_encrypt0_encode_additional_data(ctx, headermap, aad, aadLen, NULL, &sz) == COSE_OK){
            par->aadEncoded = COSE_CALLOC(ctx, sz);
            if(par->aadEncoded != NULL){
                if(cose_encrypt0_encode_additional_data(ctx, headermap, aad, aadLen, par->aadEncoded, &sz) != COSE_OK){
                    COSE_FREEF(ctx, par->aadEncoded);
                    par->aadEncoded = NULL;
                }
                par->aadLen = sz;
            }
        }
    }

    return COSE_OK;
}

cose_error_t cose_encrypt0_aead_par_encrypt_valid(cose_aead_parameters_t * par) {
    if(par == NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->key.key == NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->key.key != NULL && par->key.keyLen == 0){
        return COSE_INVALID_PARAM;
    }
    if(par->plaintext == NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->plaintext != NULL && par->plaintextLen == 0){
        return COSE_INVALID_PARAM;
    }
    if(par->aadEncoded == NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->aadEncoded != NULL && par->aadLen == 0){
        return COSE_INVALID_PARAM;
    }
    return COSE_OK;
}

cose_error_t cose_encrypt0_aead_par_valid_for(cose_aead_parameters_t * par, cose_aead_alg_t * alg) {
    if(par == NULL || alg == NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->key.keyLen != alg->keyLen){
        LOG("Keylen is not equal");
        return COSE_INVALID_PARAM;
    }
    if(par->nonceLen > alg->nonceMax || par->nonceLen < alg->nonceMin) {
        LOG("Nonce is out of range");
        return COSE_INVALID_PARAM;
    }

    return COSE_OK;
}

cose_error_t cose_encrypt0_aead_par_decrypt_valid(cose_aead_parameters_t * par) {
    if(par == NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->key.key != NULL && par->key.keyLen == 0){
        return COSE_INVALID_PARAM;
    }
    if(par->plaintext != NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->aadEncoded == NULL){
        return COSE_INVALID_PARAM;
    }
    if(par->aadEncoded != NULL && par->aadLen == 0){
        return COSE_INVALID_PARAM;
    }
    return COSE_OK;
}

cose_error_t cose_encrypt0_encrypt_uint(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, uint64_t algoId) {
    cn_cbor algId;
    memset(&algId, 0, sizeof(cn_cbor));
    algId.type = CN_CBOR_UINT;
    algId.v.uint = algoId;
    return cose_encrypt0_encrypt_cbor(ctx, msg, par, aad, aadLen, &algId);
}

cose_error_t cose_encrypt0_encrypt_cbor(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, cn_cbor const * algo) {
    if(ctx == NULL || msg == NULL || par == NULL){
        return COSE_INVALID_PARAM;
    }
    if(cose_initialized(ctx) != COSE_OK) {
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_valid(&msg->header)){
        return COSE_INVALID_PARAM;
    }
    if(par->key.key == NULL || par->key.keyLen == 0){
        LOG("Cant encrypt without key");
        return COSE_INVALID_PARAM;
    }
    if(par->plaintext == NULL){
        LOG("No plaintext supplied");
        return COSE_INVALID_PARAM;
    }
    cose_aead_alg_t * crypt = cose_aead_algorithm_find(ctx, algo);
    if(crypt == NULL){
        LOG("Requested algorithm is not available");
        return COSE_INVALID_PARAM;
    }

    if(cose_encrypt0_aead_par_encrypt_valid(par) != COSE_OK){
        cose_error_t ret = cose_encrypt0_populate_aead_par(ctx, &msg->header, par, aad, aadLen);
        if(ret != COSE_OK){
            LOG("Could not populate needed parameter");
            return ret;
        }
        ret = cose_encrypt0_aead_par_encrypt_valid(par);
        if(ret != COSE_OK){
            LOG("Not all needed parameter are available");
            return ret;
        }
    }

    if(cose_encrypt0_aead_par_valid_for(par, crypt) != COSE_OK) {
        return COSE_INVALID_PARAM;
    }

    msg->ciphertext = COSE_CALLOC(ctx, par->plaintextLen + crypt->relatingCipherTextLen);
    if(msg->ciphertext == NULL){
        return COSE_OUT_OF_MEMORY;
    }
    msg->length = par->plaintextLen + crypt->relatingCipherTextLen;

    cose_error_t ret = crypt->encrypt(par, &msg->header, msg->ciphertext);

    if(ret != COSE_OK){
        COSE_FREEF(ctx, msg->ciphertext),
        msg->ciphertext = NULL;
        msg->length = 0;
    }

    return ret;
}

cose_error_t cose_encrypt0_encrypt(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen) {
    if(msg == NULL){
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_valid(&msg->header)){
        return COSE_INVALID_PARAM;
    }

    cn_cbor * algcbor = cose_header_map_find_uint(&msg->header, COSE_HEADER_LABEL_ALG);
    if(algcbor == NULL){
        LOG("Algorithm is not specified");
        return COSE_INVALID_PARAM;
    }
    return cose_encrypt0_encrypt_cbor(ctx, msg, par, aad, aadLen, algcbor);
}

cose_error_t cose_encrypt0_decrypt_cbor(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, cn_cbor const * algo) {
    if(ctx == NULL || msg == NULL || par == NULL){
        return COSE_INVALID_PARAM;
    }
    if(cose_initialized(ctx) != COSE_OK) {
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_valid(&msg->header)){
        return COSE_INVALID_PARAM;
    }
    if(msg->ciphertext == NULL){
        LOG("No plaintext supplied");
        return COSE_INVALID_PARAM;
    }
    cose_aead_alg_t * crypt = cose_aead_algorithm_find(ctx, algo);
    if(crypt == NULL){
        LOG("Requested algorithm is not available");
        return COSE_INVALID_PARAM;
    }
    if(cose_encrypt0_aead_par_decrypt_valid(par) != COSE_OK){
        cose_error_t ret = cose_encrypt0_populate_aead_par(ctx, &msg->header, par, aad, aadLen);
        if(ret != COSE_OK){
            LOG("Could not populate needed parameter");
            return ret;
        }
        ret = cose_encrypt0_aead_par_decrypt_valid(par);
        if(ret != COSE_OK){
            LOG("Not all needed parameter are available");
            return ret;
        }
    }
    
    par->plaintext = COSE_CALLOC(ctx, msg->length - crypt->relatingCipherTextLen);
    if(par->plaintext == NULL){
        return COSE_OUT_OF_MEMORY;
    }
    par->plaintextLen = msg->length - crypt->relatingCipherTextLen;
    cose_error_t ret = COSE_AUTH_FAILED;
    if(par->key.key == NULL){
        cn_cbor * algValue = cose_header_map_find_uint(&msg->header, COSE_HEADER_LABEL_ALG);
        cn_cbor * kid = cose_header_map_find_uint(&msg->header, COSE_HEADER_LABEL_KID);
        if(algValue != NULL && kid != NULL && kid->type == CN_CBOR_BYTES){
            cose_identifyable_key_t * identkey = cose_aead_algorithm_find_key_bykid(crypt->keys, kid->v.bytes, kid->length);
            while(identkey != NULL && ret != COSE_OK) {
                par->key.key = identkey->keydata.key;
                par->key.keyLen = identkey->keydata.keyLen;
                if(cose_encrypt0_aead_par_valid_for(par, crypt) == COSE_OK){
                    ret = crypt->decrypt(par, &msg->header, msg->ciphertext, msg->length);
                }
                par->key.key = NULL;
                par->key.keyLen = 0;
                identkey = cose_aead_algorithm_find_key_bykid(identkey->next, kid->v.bytes, kid->length);
            }
        }
        else {
            LOG("Could not find key");
            ret = COSE_INVALID_PARAM;
        }
    }
    else {
        if(cose_encrypt0_aead_par_valid_for(par, crypt) == COSE_OK){
            ret = crypt->decrypt(par, &msg->header, msg->ciphertext, msg->length);
        }
    }

    if(ret != COSE_OK){
        COSE_FREEF(ctx, par->plaintext),
        par->plaintext = NULL;
        par->plaintextLen = 0;
    }

    return ret;
}

cose_error_t cose_encrypt0_decrypt_uint(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen, uint64_t algoId) {
    cn_cbor algId;
    memset(&algId, 0, sizeof(cn_cbor));
    algId.type = CN_CBOR_UINT;
    algId.v.uint = algoId;
    return cose_encrypt0_decrypt_cbor(ctx, msg, par, aad, aadLen, &algId);
}

cose_error_t cose_encrypt0_decrypt(cose_context_t *ctx, cose_encrypt0_t * msg, cose_aead_parameters_t * par, uint8_t const * aad, size_t aadLen) {
    if(msg == NULL){
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_valid(&msg->header)){
        return COSE_INVALID_PARAM;
    }

    cn_cbor * algcbor = cose_header_map_find_uint(&msg->header, COSE_HEADER_LABEL_ALG);
    if(algcbor == NULL){
        LOG("Algorithm is not specified");
        return COSE_INVALID_PARAM;
    }
    return cose_encrypt0_decrypt_cbor(ctx, msg, par, aad, aadLen, algcbor);
}

cose_error_t cose_encrypt0_serialize(cose_context_t *ctx, cose_encrypt0_t * msg, uint8_t * out, size_t * len) {
    if(ctx == NULL || len == NULL || msg == NULL || msg->ciphertext == NULL || msg->length == 0){
        return COSE_INVALID_PARAM;
    }
    if(cose_initialized(ctx) != COSE_OK){
        return COSE_INVALID_PARAM;
    }
    if(cose_header_map_valid(&msg->header) != 1) {
        return -1;
    }
    CBOR_CONTEXT_INIT(ctx)

    cn_cbor encrypt0;
    memset(&encrypt0, 0, sizeof(cn_cbor));
    encrypt0.type = CN_CBOR_ARRAY;
    encrypt0.flags |= CN_CBOR_FL_COUNT | CN_CBOR_FL_EXT_SELF;

    cn_cbor prot;
    memset(&prot, 0, sizeof(cn_cbor));
    cose_error_t ret = cose_header_map_serialize(ctx, &msg->header, &prot);
    prot.flags |= CN_CBOR_FL_EXT_SELF;
    if(ret != COSE_OK){
        return ret;
    }

    if(!cn_cbor_array_append(&encrypt0, &prot, NULL)) {
        cn_cbor_free(&prot, CBOR_CONTEXT_INSERT);
        ret = COSE_UNDEFINED_CBOR_ERROR;
        goto error;
    }
    if(!cn_cbor_array_append(&encrypt0, &msg->header.unprot, NULL)) {
        ret = COSE_UNDEFINED_CBOR_ERROR;
        goto error;
    }
    cn_cbor cipher;
    memset(&cipher, 0, sizeof(cn_cbor));
    cipher.flags |= CN_CBOR_FL_EXT_SELF | CN_CBOR_FL_EXT_DATA;
    cipher.type = CN_CBOR_BYTES;
    cipher.v.bytes = msg->ciphertext;
    cipher.length = msg->length;
    if(!cn_cbor_array_append(&encrypt0, &cipher, NULL)) {
        ret = COSE_UNDEFINED_CBOR_ERROR;
        goto error;
    }
    ssize_t cborReturn = 0;
    cborReturn = cn_cbor_encoder_write(NULL, 0, 0, &encrypt0);
    if(cborReturn <= 0){
        ret = COSE_UNDEFINED_CBOR_ERROR;
        goto error;
    }
    if(out != NULL && *len >= ret){
        cborReturn = cn_cbor_encoder_write(out, 0, *len, &encrypt0);
    }
    if(out != NULL && *len < ret){
        LOG("Buffer too small");
        ret = COSE_OUT_OF_MEMORY;
        goto error;
    }

    if(cborReturn > 0){
        *len = cborReturn;
        ret = COSE_OK;
    }
    else {
        ret = COSE_UNDEFINED_CBOR_ERROR;
    }
error:
    cbor_remove_from_array(&encrypt0, &msg->header.unprot);
    cn_cbor_free(&encrypt0, CBOR_CONTEXT_INSERT);
    return ret;
}

cose_error_t cose_encrypt0_parse(cose_context_t *ctx, cose_encrypt0_t * msg, uint8_t const * in, size_t len) {
    if(ctx == NULL || msg == NULL || in == NULL || len == 0) {
        return COSE_INVALID_PARAM;
    }
    if(cose_initialized(ctx) != COSE_OK) {
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_valid(&msg->header) || (msg->header.prot.length > 0 || msg->header.unprot.length > 0)) {
        LOG("Header of message must be initialized, but empty");
        return COSE_INVALID_PARAM;
    }
    CBOR_CONTEXT_INIT(ctx)
    cose_error_t ret = 0;
    cn_cbor* encrypt0 = cn_cbor_decode(in, len, CBOR_CONTEXT_INSERT, NULL);
    if(encrypt0 == NULL){
        LOG("Could not parse input");
        return COSE_CBOR_INVALID_FORMAT;
    }
    if(encrypt0->type != CN_CBOR_ARRAY || encrypt0->length != 3) {
        LOG("parsed object is not array or has invalid length");
        ret = COSE_CBOR_INVALID_FORMAT;
        goto error;
    }
    cn_cbor* prot = cn_cbor_index(encrypt0, 0);
    cn_cbor* unprot = cn_cbor_index(encrypt0, 1);
    cn_cbor* ciphertext = cn_cbor_index(encrypt0, 2);
    if(prot == NULL || prot->type != CN_CBOR_BYTES){
        LOG("protected bucket is not encoded as bytestring");
        ret = COSE_CBOR_INVALID_FORMAT;
        goto error;
    }
    if(unprot == NULL || unprot->type != CN_CBOR_MAP){
        LOG("unprotected bucket was not encoded as map");
        ret = COSE_CBOR_INVALID_FORMAT;
        goto error;
    }
    if(ciphertext == NULL || ciphertext->type != CN_CBOR_BYTES || ciphertext->length == 0){
        LOG("ciphertext not encoded as bytestring");
        ret = COSE_CBOR_INVALID_FORMAT;
        goto error;
    }
    if(prot->length > 0) {
        // parse protected map
        cn_cbor* protMap = cn_cbor_decode(prot->v.bytes, prot->length, CBOR_CONTEXT_INSERT, NULL);
        if(protMap == NULL || protMap->type != CN_CBOR_MAP){
            LOG("decoded protected bytestring is not a map");
            ret = COSE_CBOR_INVALID_FORMAT;
            goto error;
        }
        memcpy(&msg->header.prot, protMap, sizeof(cn_cbor));
        msg->header.prot.flags |= CN_CBOR_FL_EXT_SELF;
        cn_cbor * itor = protMap->first_child;
        // fix parents
        while(itor != NULL){
            itor->parent = &msg->header.prot;
            itor = itor->next;
        }
        //change type of parsed map and free it
        memset(protMap, 0, sizeof(cn_cbor));
        protMap->type = CN_CBOR_UINT;
        cn_cbor_free(protMap, CBOR_CONTEXT_INSERT);
    }
    //add unprotected map to own datastructure
    if(!cbor_remove_from_array(encrypt0, unprot)) { 
        ret = COSE_UNDEFINED_CBOR_ERROR;
        goto error;
    }
    memcpy(&msg->header.unprot, unprot, sizeof(cn_cbor));
    // copy bytes to new buffer, to be able to free message with provided free function
    msg->ciphertext = COSE_CALLOC(ctx, ciphertext->length);
    if(msg->ciphertext == NULL){
        ret = COSE_OUT_OF_MEMORY;
        goto error;
    }
    memcpy(msg->ciphertext, ciphertext->v.bytes, ciphertext->length);
    msg->length = ciphertext->length;
    ret = COSE_OK;

error:
    if(encrypt0 != NULL){
        cn_cbor_free(encrypt0, CBOR_CONTEXT_INSERT);
    }

    return ret;
}