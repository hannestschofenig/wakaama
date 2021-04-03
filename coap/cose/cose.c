#include "cose/cose.h"
#include "cose/cose_util.h"
#include <string.h>


cose_error_t cose_init(cose_context_t * context, cose_calloc_func_t calloc_func, cose_free_func_t free_func, void * userContext) {
    if(context == NULL) {
        LOG("called with null");
        return COSE_INVALID_PARAM;
    }
    if(calloc_func == NULL || free_func == NULL) {
        LOG("called without memory manager functions");
        return COSE_INVALID_PARAM;
    }
    memset(context, 0, sizeof(cose_context_t));
    context->calloc_func = calloc_func;
    context->free_func = free_func;
    context->userContext = userContext;
    return COSE_OK;
}

cose_error_t cose_initialized(cose_context_t const * context) {
    if(context == NULL){
        return COSE_INVALID_PARAM;
    }
    if(context->calloc_func == NULL || context->free_func == NULL){
        return COSE_INVALID_PARAM;
    }
    return COSE_OK;
}

void cose_free(cose_context_t * context) {
    if(cose_initialized(context) != COSE_OK){
        return;
    }
    
    cose_aead_alg_t * itorAlg = context->aead;
    cose_aead_alg_t * oldItorAlg = itorAlg;
    while(itorAlg != NULL){
        oldItorAlg = itorAlg;
        cose_aead_alg_free(context, itorAlg);

        itorAlg = itorAlg->next;
        COSE_FREEF(context, oldItorAlg);
    }
    memset(context, 0, sizeof(cose_context_t));
}

void cose_aead_alg_free(cose_context_t * ctx, cose_aead_alg_t * alg) {
    if(alg == NULL){
        return;
    }
    cose_identifyable_key_t * itor = alg->keys;
    cose_identifyable_key_t * oldItor = itor;
    while(itor != NULL){
        oldItor = itor;
        if(itor->kid != NULL){
            COSE_FREEF(ctx, itor->kid);
        }
        itor = itor->next;
        COSE_FREEF(ctx, oldItor);
    }
    memset(alg, 0, sizeof(cose_aead_alg_t));
}

cose_error_t cose_aead_algorithm_valid(cose_aead_alg_t const * alg) {
    if(alg == NULL) {
        return COSE_INVALID_PARAM;
    }
    if(!cose_algorithm_valid_identifier(&alg->id)) {
        return COSE_INVALID_PARAM;
    }
    if(alg->encrypt == NULL || alg->decrypt == NULL){
        return COSE_INVALID_PARAM;
    }
    if(alg->keyLen == 0){
        return COSE_INVALID_PARAM;
    }
    if(alg->nonceMin > alg->nonceMax){
        return COSE_INVALID_PARAM;
    }

    return COSE_OK;
}

cose_aead_alg_t * cose_aead_algorithm_find(cose_context_t * context, cn_cbor const * id) {
    if(context == NULL || id == NULL){
        return NULL;
    }
    if(!cose_algorithm_valid_identifier(id)) {
        LOG("Cant find algorithm with invalid id");
        return NULL;
    }
    cose_aead_alg_t * itor = context->aead;
    while(itor != NULL){
        if(cbor_is_same(id, &itor->id)) {
            return itor;
        }
        itor = itor->next;
    }
    return NULL;
}

cose_error_t cose_aead_algorithm_add(cose_context_t * context, cose_aead_alg_t * alg) {
    if(cose_aead_algorithm_valid(alg) != COSE_OK || context == NULL){
        return COSE_INVALID_PARAM;
    }
    if(alg->keys != NULL || alg->next != NULL){
        LOG("Tried to add multiple algorithms or keys");
        return COSE_INVALID_PARAM;
    }
    if(cose_aead_algorithm_find(context, &alg->id) != NULL){
        LOG("Tried to add same algorithm twice");
        return COSE_ALREADY_AVAILABLE;
    }

    if(context->aead == NULL){
        context->aead = alg;
        return COSE_OK;
    }

    cose_aead_alg_t * itor = context->aead;
    while(itor->next != NULL){
        itor = itor->next;
    }
    itor->next = alg;

    return COSE_OK;
}

cose_error_t cose_aead_algorithm_add_key(cose_context_t * context, cn_cbor const * id, cose_identifyable_key_t * key) {
    if(key == NULL){
        return COSE_INVALID_PARAM;
    }
    cose_aead_alg_t * alg = cose_aead_algorithm_find(context, id);
    if(alg == NULL) {
        LOG("Cant add key to unknown algorithm");
        return COSE_INVALID_PARAM;
    }
    if(!cose_aead_algorithm_valid_key(alg, key)){
        LOG("Key has invalid parameter");
        return COSE_INVALID_PARAM;
    }

    key->next = alg->keys;
    alg->keys = key;

    return COSE_OK;
}

cose_identifyable_key_t * cose_aead_algorithm_find_key_bykid(cose_identifyable_key_t * begin, uint8_t const * kid, size_t kidLen) {
    if(kid == NULL || kidLen == 0) {
        LOG("Cant find key without kid");
        return NULL;
    }
    cose_identifyable_key_t * itor = begin;
    while(itor != NULL){
        if(itor->kidLen == kidLen){
            if(memcmp(itor->kid, kid, kidLen) == 0){
                return itor;
            }
        }
        itor = itor->next;
    }
    return NULL;
}

bool cose_aead_algorithm_valid_key(cose_aead_alg_t const * alg, cose_identifyable_key_t const * key) {
    if(alg == NULL || key == NULL || key->keydata.key == NULL || key->kid == NULL || key->kidLen == 0){
        return false;
    }
    if(alg->keyLen != key->keydata.keyLen){
        return false;
    }
    return true;
}