#include "oscore/oscore.h"
#include "cose/cose_util.h"
#include "er-coap-13/er-coap-13.h"
#include <stdlib.h>
#include "liblwm2m.h"
#include <string.h>
#include <assert.h>

static void ntworder(uint8_t * buffer, void * insert, size_t const size) {
#ifdef LWM2M_BIG_ENDIAN
    mempcy(buffer, insert, size);
#else
    for (size_t i = 0; i < size; i++)
    {
        buffer[i] = ((uint8_t *)insert)[size - 1 - i];
    }
#endif
}

typedef struct oscore_option_itor{
    uint8_t const * value;
    uint16_t valueLength;
    coap_option_t option;
    uint8_t * beginOption;

    uint8_t * nextOption;
    size_t length;
    uint8_t * buffer;
} oscore_option_itor_t;

static int oscore_option_itor_init(oscore_option_itor_t * itor, uint8_t * buffer, size_t length) {
    memset(itor, 0, sizeof(oscore_option_itor_t));
    if(length < 4) {
        return -1;
    }
    uint8_t tokenlength = buffer[0] & 0x0F;
    if(tokenlength > 8) {
        return -1;
    }
    if(length < (size_t)(4 + tokenlength)) {
        return -1;
    }
    itor->buffer = buffer;
    itor->length = length;
    itor->nextOption = buffer + 4 + tokenlength;
    return 0;
}

static int oscore_option_itor_next(oscore_option_itor_t * itor) {
    itor->beginOption = itor->nextOption;
    if(*(itor->beginOption) == 0xFF) {
        itor->option = OPTION_MAX_VALUE;
        return 0;
    }
    if(itor->beginOption - itor->buffer >= (int)itor->length) {
        itor->option = OPTION_MAX_VALUE;
        return 0;
    }
    uint8_t const optionDelta = (*(itor->beginOption) & 0xF0) >> 4;
    uint8_t const optionLength = *(itor->beginOption) & 0x0F;
    if(optionDelta == 0x0F || optionLength == 0x0F) {
        // invalid format
        return -1;
    }
    uint8_t * pos = itor->beginOption;

    uint16_t delta = optionDelta;
    uint16_t length = optionLength;
    pos++;
    if(optionDelta == 13) {
        delta = (*pos) + 13;
        pos++;
    }
    else if(optionDelta == 14) {
        ntworder((uint8_t*)&delta, pos, 2);
        delta += 269;
        pos += 2;
    }
    if(optionLength == 13) {
        length = (*pos) + 13;
        pos++;
    }
    else if(optionLength == 14) {
        ntworder((uint8_t*)&length, pos, 2);
        length += 269;
        pos += 2;
    }
    itor->option = itor->option + delta;
    itor->valueLength = length;
    itor->value = pos;
    itor->nextOption = pos + length;

    return 1;
}



int coap_set_header_oscore(void * packet, uint8_t const * partialIV, uint8_t partialIVLen, uint8_t const * kidContext, uint8_t kidContextLen, uint8_t const * kid, uint8_t kidLen) {
    coap_packet_t *const coap_pkt = (coap_packet_t *) packet;
    size_t maxLength = 1 + partialIVLen;
    if(partialIVLen > OSCORE_PARTIALIV_MAXLEN){
        return 0;
    }
    if(kidContextLen != 0){
        maxLength += 1 + kidContextLen;
    }
    maxLength += kidLen;
    if(maxLength > OSCORE_OPTION_VALUE_MAXLEN) {
        return 0;
    }
    coap_pkt->oscore_partialIV = partialIV;
    coap_pkt->oscore_partialIVLen = partialIVLen;
    coap_pkt->oscore_kidContext = kidContext;
    coap_pkt->oscore_kidContextLen = kidContextLen;
    coap_pkt->oscore_kid = kid;
    coap_pkt->oscore_kidLen = kidLen;
    SET_OPTION(coap_pkt, COAP_OPTION_OSCORE);

    return 1;
}

int coap_get_header_oscore(void * packet, uint8_t const ** partialIV, uint8_t * partialIVLen, uint8_t const ** kidContext, uint8_t * kidContextLen, uint8_t const ** kid, uint8_t *kidLen) {
    coap_packet_t *const coap_pkt = (coap_packet_t *) packet;

    if(partialIV != NULL && partialIVLen != NULL){
        *partialIV = coap_pkt->oscore_partialIV;
        *partialIVLen = coap_pkt->oscore_partialIVLen;
    }
    if(kidContext != NULL && kidContextLen != NULL){
        *kidContext = coap_pkt->oscore_kidContext;
        *kidContextLen = coap_pkt->oscore_kidContextLen;
    }
    if(kid != NULL && kidLen != NULL){
        *kid = coap_pkt->oscore_kid;
        *kidLen = coap_pkt->oscore_kidLen;
    }
    
    return 1;
}

int coap_parse_oscore_option(void * packet, uint8_t const * value, uint32_t const optionLength) {
    coap_packet_t *const coap_pkt = (coap_packet_t *) packet;
    int kidLen = optionLength - 1;
    // first header byte must be added as well
    uint32_t maxLength = 1;
    int idx = 0;
    if(optionLength == 0){
        return 0;
    }
    if(optionLength > OSCORE_OPTION_VALUE_MAXLEN) {
        return BAD_OPTION_4_02;
    }
    coap_pkt->oscore_partialIVLen = (value[0] & 0x7);
    if(optionLength < (uint32_t)(coap_pkt->oscore_partialIVLen + 1)) {
        return BAD_OPTION_4_02;
    }
    kidLen -= coap_pkt->oscore_partialIVLen;
    maxLength += coap_pkt->oscore_partialIVLen;
    if((value[0] & 0x10)) { // kid context available
        coap_pkt->oscore_kidContext = OSCORE_EMPTY_ENTRY;
        coap_pkt->oscore_kidContextLen = value[1+coap_pkt->oscore_partialIVLen];
        kidLen -= (coap_pkt->oscore_kidContextLen + 1);
        maxLength += (coap_pkt->oscore_kidContextLen + 1);
    }
    if((value[0] & 0x08)) { // kid available
        if(kidLen < 0) {
            return BAD_OPTION_4_02;
        }
        coap_pkt->oscore_kid = OSCORE_EMPTY_ENTRY;
        coap_pkt->oscore_kidLen = kidLen;
        maxLength += coap_pkt->oscore_kidLen;
    }

    if(maxLength > optionLength) { //wrongly encoded optionvalue
        return BAD_OPTION_4_02;
    }

    idx = 1;
    if(coap_pkt->oscore_partialIVLen > 0){
        coap_pkt->oscore_partialIV = value + idx;
        idx += coap_pkt->oscore_partialIVLen;
    }
    if(coap_pkt->oscore_kidContextLen > 0) {
        coap_pkt->oscore_kidContext = value + idx + 1;
        idx += coap_pkt->oscore_kidContextLen;
    }
    if((value[0] & 0x10)) { // s could be 0
        idx++;
    }
    if(coap_pkt->oscore_kidLen > 0) {
        coap_pkt->oscore_kid = value + idx;
    }

    return 0;
}


int oscore_additional_authenticated_data_get_size(cn_cbor const * algo, uint8_t const * kid, uint8_t const kidLen, uint8_t const * partialIV, uint8_t const partialIVLen) {
    return oscore_additional_authenticated_data_serialize(NULL, 0, algo, kid, kidLen, partialIV, partialIVLen);
}

int oscore_additional_authenticated_data_serialize(uint8_t * buffer, size_t const length, cn_cbor const * algo, uint8_t const * kid, uint8_t const kidLen, uint8_t const * partialIV, uint8_t const partialIVLen) {
    static uint8_t const prefix[] = {
        0x83, 0x68, 0x45, 0x6e,
        0x63, 0x72, 0x79, 0x70,
        0x74, 0x30, 0x40
    };
    cn_cbor * algorithms = NULL;
    cn_cbor algorithmsArray;
    cn_cbor oscoreVersion;
    cn_cbor kidcbor;
    cn_cbor partialIVcbor;
    cn_cbor options;
    cn_cbor ad;
    memset(&oscoreVersion, 0, sizeof(cn_cbor));
    memset(&algorithmsArray, 0, sizeof(cn_cbor));
    memset(&kidcbor, 0, sizeof(cn_cbor));
    memset(&partialIVcbor, 0, sizeof(cn_cbor));
    memset(&options, 0, sizeof(cn_cbor));
    memset(&ad, 0, sizeof(cn_cbor));
    
    oscoreVersion.type = CN_CBOR_UINT;
    oscoreVersion.v.uint = 1;

    if(algo->type == CN_CBOR_ARRAY) {
        algorithms = (cn_cbor*)algo;
    }
    else {
        algorithmsArray.type = CN_CBOR_ARRAY;
	    algorithmsArray.flags |= CN_CBOR_FL_COUNT;
        cn_cbor_array_append(&algorithmsArray, (cn_cbor*)algo, NULL);
        algorithms = &algorithmsArray;
    }
    kidcbor.type = CN_CBOR_BYTES;
    kidcbor.v.bytes = kid;
    kidcbor.length = kidLen;

    partialIVcbor.type = CN_CBOR_BYTES;
    partialIVcbor.v.bytes = partialIV;
    partialIVcbor.length = partialIVLen;

    options.type = CN_CBOR_BYTES;

    ad.type = CN_CBOR_ARRAY;
	ad.flags |= CN_CBOR_FL_COUNT;

    cn_cbor_array_append(&ad, &oscoreVersion, NULL);
    cn_cbor_array_append(&ad, algorithms, NULL);
    cn_cbor_array_append(&ad, &kidcbor, NULL);
    cn_cbor_array_append(&ad, &partialIVcbor, NULL);
    cn_cbor_array_append(&ad, &options, NULL);
    
    int aadLen = cn_cbor_encoder_write(buffer, 0, length, &ad);
    if(aadLen < 0){
        return -1;
    }
    size_t extraLength = 1; // length needed for cbor byte string encoding
    if(aadLen >= 24) {
        if(aadLen <= UINT8_MAX) { // cbor bytestring length encoding in following byte
            extraLength += 1;
        }
        else if(aadLen <= UINT16_MAX) { // cbor bytestring length encoding in following two bytes
            extraLength += 2;
        }
        else {
            // this could lead to out of memory. Do not support larger arrays.
            return -1;
        }
    }
    if(buffer != NULL){
        if(length < aadLen + extraLength + sizeof(prefix)){
            return -1;
        }
        memmove(buffer + sizeof(prefix) + extraLength, buffer, aadLen);
        buffer[sizeof(prefix)] = 0x40;
        uint16_t const len2Byte = aadLen;
        uint8_t const len1Byte = aadLen;
        if(aadLen < 24) {
            buffer[sizeof(prefix)] |= aadLen;
        }
        else if(aadLen <= UINT8_MAX) {
            buffer[sizeof(prefix)+1] = len1Byte;
        }
        else if(aadLen <= UINT16_MAX) {
            ntworder(buffer+sizeof(prefix)+1, (void*)&len2Byte, 2);
        }
        memcpy(buffer, prefix, sizeof(prefix));
    }


    // one byte for cbor bytestring major tag + 11 bytes for ENC Structure
    return aadLen + extraLength + sizeof(prefix);
}



static void * oscore_internal_calloc(size_t count, size_t size, void* context) {
    (void)context;
    void * ret = lwm2m_malloc(count*size);
    if(ret != NULL){
        memset(ret, 0, count*size);
    }
    return ret;
}

static void oscore_internal_free(void*ptr, void *context) {
    (void)context;
    lwm2m_free(ptr);
}



void oscore_init(oscore_context_t * ctx) {
    if(ctx != NULL){
        memset(ctx,0,sizeof(oscore_context_t));
#ifdef OSCORE_BACKEND
        oscore_backend_init(ctx);
#endif
    cose_init(&ctx->cose, oscore_internal_calloc, oscore_internal_free, NULL);
    }
}

void oscore_free(oscore_context_t * ctx) {
#ifdef OSCORE_BACKEND
    oscore_backend_free(ctx);
#endif
    cose_free(&ctx->cose);
    while(ctx->sentRequest != NULL) {
        oscore_request_mapping_t * del = ctx->sentRequest;
        ctx->sentRequest = del->next;
        OSCORE_FREE(del);
    }
    while(ctx->receivedRequest != NULL) {
        oscore_request_mapping_t * del = ctx->receivedRequest;
        ctx->receivedRequest = del->next;
        OSCORE_FREE(del);
    }
}

static oscore_request_mapping_t * oscore_internal_request_step(oscore_request_mapping_t * begin, time_t * timeoutP) {
    time_t now = time(NULL);
    oscore_request_mapping_t * itor = begin;
    while(itor != NULL){
        if(itor->timeout < now) {
            oscore_request_mapping_t * del = itor;
            itor = itor->next;
            begin = oscore_remove_request(begin, del);
            OSCORE_FREE(del);
        }
        else if(itor->timeout - now < *timeoutP) {
            *timeoutP = itor->timeout - now;
            itor = itor->next;
        }
        else{
            itor = itor->next;
        }
    }
    return begin;
}

void oscore_step(oscore_context_t * ctx, time_t * timeoutP) {
    ctx->sentRequest = oscore_internal_request_step(ctx->sentRequest, timeoutP);
    ctx->receivedRequest = oscore_internal_request_step(ctx->receivedRequest, timeoutP);
    
}

int oscore_hkdf_algorithm_add(oscore_context_t * ctx, oscore_hkdf_alg_t * hkdf) {
    if(ctx == NULL || hkdf == NULL){
        return -1;
    }
    if(ctx->hkdf == NULL){
        ctx->hkdf = hkdf;
        return 0;
    }
    assert(hkdf->size <= OSCORE_HKDF_MAXLEN);
    oscore_hkdf_alg_t * itor = ctx->hkdf;
    while(itor->next != NULL){
        if(cbor_is_same(&hkdf->id, &itor->id)) {
            return -1;
        }
        itor = itor->next;
    }
    itor->next = hkdf;
    return 0;
}

int oscore_hkdf_algorithm_rm(oscore_context_t * ctx, cn_cbor * id, oscore_hkdf_alg_t ** out) {
    if(ctx == NULL || id == NULL || ctx->hkdf == NULL) {
        return -1;
    }
    if(cbor_is_same(&ctx->hkdf->id, id)) {
        if(out != NULL){
            *out = ctx->hkdf;
        }
        ctx->hkdf = ctx->hkdf->next;
        return 0;
    }
    if(ctx->hkdf->next == NULL){
        return -1;
    }
    oscore_hkdf_alg_t * itor = ctx->hkdf;
    while(itor->next != NULL && !cbor_is_same(&itor->next->id, id)) {
        itor = itor->next;
    }
    
    if(itor->next == NULL){
        return -1;
    }
    if(out != NULL){
        *out = itor->next;
    }
    itor->next = itor->next->next;
    return 0;
}

oscore_hkdf_alg_t * oscore_hkdf_algorithm_find(oscore_context_t * ctx, cn_cbor const * id) {
    if(ctx == NULL || id == NULL) {
        return NULL;
    }
    oscore_hkdf_alg_t * itor = ctx->hkdf;
    while(itor != NULL) {
        if(cbor_is_same(&itor->id, id)) {
            return itor;
        }
        itor = itor->next;
    }
    return NULL;
}


int oscore_derive_context(oscore_context_t * ctx, oscore_common_context_t const * commonCtx, oscore_derived_context_t * derivedCtx) {
    if(ctx == NULL || commonCtx == NULL || derivedCtx == NULL){
        return -1;
    }
    uint8_t prk[OSCORE_HKDF_MAXLEN];
    char const typeKey[] = "Key";
    char const typeIV[] = "IV";
    if(commonCtx->senderIdLen > OSCORE_MAX_ID_LEN || commonCtx->recipientIdLen > OSCORE_MAX_ID_LEN) {
        LOG("Sender or recipient Id out of range");
        return -1;
    }

    oscore_hkdf_alg_t * hkdf = oscore_hkdf_algorithm_find(ctx, &commonCtx->hkdfAlgId);
    cose_aead_alg_t * aead = cose_aead_algorithm_find(&ctx->cose, &commonCtx->aeadAlgId);

    if(hkdf == NULL || aead == NULL) {
        LOG("requested HKDF or AEAD algorithm is missing");
        return -1;
    }

    derivedCtx->keyLen = aead->keyLen;
    derivedCtx->nonceLen = aead->nonceMin;

    uint8_t const * salt = commonCtx->masterSalt;
    size_t const saltLen = commonCtx->masterSaltLen;
    uint8_t const * ikm = commonCtx->masterSecret; 
    uint8_t const ikmLen = commonCtx->masterSecretLen;
    
    if(hkdf->extract(salt, saltLen, ikm, ikmLen, prk) != 0) {
        return -1;
    }

    // calculate maximum length of info
    int maxInfoLength = 0;

    cn_cbor info;
    memset(&info, 0, sizeof(cn_cbor));
    info.type = CN_CBOR_ARRAY;
    info.flags |= CN_CBOR_FL_COUNT;

    cn_cbor id;
    memset(&id, 0, sizeof(cn_cbor));
    id.type = CN_CBOR_BYTES;
    cn_cbor id_context;
    memset(&id_context, 0, sizeof(cn_cbor));
    if(commonCtx->idContextLen == 0){
        id_context.type = CN_CBOR_NULL;
        maxInfoLength += 1; // cbor null value
    }
    else{
        id_context.type = CN_CBOR_BYTES;
        id_context.v.bytes = commonCtx->idContext;
        id_context.length = commonCtx->idContextLen;
        maxInfoLength += 3 + commonCtx->idContextLen; // cbor bytestring + 2 bytes for length
    }
    cn_cbor type;
    memset(&type, 0, sizeof(cn_cbor));
    type.type = CN_CBOR_TEXT;
    cn_cbor L;
    memset(&L, 0, sizeof(cn_cbor));
    L.type = CN_CBOR_UINT;

    cn_cbor_array_append(&info, &id, NULL);
    cn_cbor_array_append(&info, &id_context, NULL);
    cn_cbor_array_append(&info, (cn_cbor*)&commonCtx->aeadAlgId, NULL);
    cn_cbor_array_append(&info, &type, NULL);
    cn_cbor_array_append(&info, &L, NULL);

    

    maxInfoLength += 3 + OSCORE_MAX_ID_LEN;
    maxInfoLength += 9; // cbor encoded aead alg (currently no string algorithms are defined, int value algorithms should be less than 2^32)
    maxInfoLength += 4; // cbor encoded type
    maxInfoLength += 2; // cbor encoded L (all known keylength or noncelength are less than 255 until now)
    maxInfoLength += 1; // cbor encoded array type with 5 elements
    
    uint8_t * serializedInfo = OSCORE_MALLOC(maxInfoLength);
    if(serializedInfo == NULL){
        LOG("Out of memory");
        return -1;
    }

    // set info for sender key
    id.v.bytes = commonCtx->senderId;
    id.length = commonCtx->senderIdLen;
    type.v.str = typeKey;
    type.length = 3;
    L.v.uint = derivedCtx->keyLen;
    
    int ret = cn_cbor_encoder_write(serializedInfo, 0, maxInfoLength, &info);
    if(ret < 0){
        LOG("Could not serialize cbor of info. Maybe invalid buffer size?")
        OSCORE_FREE(serializedInfo);
        return -1;
    }

    if(hkdf->expand(prk, hkdf->size, serializedInfo, ret, derivedCtx->senderKey, derivedCtx->keyLen) != 0) {
        OSCORE_FREE(serializedInfo);
        return -1;
    }

    // set info for recipient key
    id.v.bytes = commonCtx->recipientId;
    id.length = commonCtx->recipientIdLen;

    ret = cn_cbor_encoder_write(serializedInfo, 0, maxInfoLength, &info);
    if(ret < 0){
        OSCORE_FREE(serializedInfo);
        return -1;
    }

    if(hkdf->expand(prk, hkdf->size, serializedInfo, ret, derivedCtx->recipientKey, derivedCtx->keyLen) != 0) {
        OSCORE_FREE(serializedInfo);
        return -1;
    }

    // set info for recipient key
    id.v.bytes = NULL;
    id.length = 0;
    type.v.str = typeIV;
    type.length = 2;
    L.v.uint = derivedCtx->nonceLen;

    ret = cn_cbor_encoder_write(serializedInfo, 0, maxInfoLength, &info);
    if(ret < 0){
        OSCORE_FREE(serializedInfo);
        return -1;
    }

    if(hkdf->expand(prk, hkdf->size, serializedInfo, ret, derivedCtx->commonIV, derivedCtx->nonceLen) != 0) {
        OSCORE_FREE(serializedInfo);
        return -1;
    }
    OSCORE_FREE(serializedInfo);

    return 0;
}


int oscore_derive_nonce(uint8_t const * id, size_t idLen, uint8_t const * commonIV, size_t commonIVLen, uint8_t const * partialIV, size_t partialIVLen, uint8_t * nonce) {
    if(commonIV == NULL || nonce == NULL){
        return -1;
    }
    uint8_t buf1[OSCORE_MAXNONCELEN];
    memset(buf1, 0, OSCORE_MAXNONCELEN);
    buf1[0] = idLen;
    if(idLen > OSCORE_MAX_ID_LEN) {
        LOG("Id is out of range");
        return -1;
    }
    if(commonIVLen > OSCORE_MAXNONCELEN) {
        LOG("CommonIV is out of range");
        return -1;
    }
    if(partialIVLen > OSCORE_PARTIALIV_MAXLEN){
        LOG("PartialIV is out of range");
        return -1;
    }
    if(id != NULL) {
        memcpy(buf1+1+OSCORE_MAX_ID_LEN-idLen, id, idLen);
    }
    
    if(partialIV != NULL){
        memcpy(buf1 + commonIVLen - partialIVLen, partialIV, partialIVLen);
    }
    for(size_t i = 0; i < commonIVLen; i++) {
        nonce[i] = buf1[i] ^ commonIV[i];
    }
    return 0;
}


static coap_option_t const OSCORE_E_OPTIONS[] = {
    COAP_OPTION_IF_MATCH,
    COAP_OPTION_ETAG,
    COAP_OPTION_IF_NONE_MATCH,
    COAP_OPTION_OBSERVE,
    COAP_OPTION_LOCATION_PATH,
    COAP_OPTION_URI_PATH,
    COAP_OPTION_CONTENT_TYPE,
    COAP_OPTION_MAX_AGE,
    COAP_OPTION_URI_QUERY,
    COAP_OPTION_ACCEPT,
    COAP_OPTION_LOCATION_QUERY,
    COAP_OPTION_BLOCK2,
    COAP_OPTION_BLOCK1,
};

static coap_option_t const OSCORE_U_OPTIONS[] = {
    COAP_OPTION_URI_HOST,
    COAP_OPTION_URI_PORT,
    COAP_OPTION_OSCORE,
    COAP_OPTION_PROXY_URI,
    COAP_OPTION_PROXY_SCHEME
};

static bool oscore_internal_is_EOption(coap_option_t op) {
    for(size_t i = 0; i < sizeof(OSCORE_U_OPTIONS)/sizeof(coap_option_t); i++) {
        if(op == OSCORE_U_OPTIONS[i]) {
            return false;
        }
    }
    return true;
}

static coap_option_t oscore_internal_get_next_EOption(coap_packet_t * packet) {
    for(size_t i = 0; i < sizeof(OSCORE_E_OPTIONS)/sizeof(coap_option_t); i++) {
        if(IS_OPTION(packet, OSCORE_E_OPTIONS[i])) {
            return OSCORE_E_OPTIONS[i];
        }
    }
    return OPTION_MAX_VALUE;
}

static void oscore_internal_u64_to_partialIV(uint64_t v, uint8_t * partialIV, size_t * partialIVLen) {
    *partialIVLen = 0;
#ifdef LWM2M_BIG_ENDIAN
    memcpy(partialIV, &v, sizeof(uint64_t));
#else
    ntworder(partialIV, &v, sizeof(uint64_t));
#endif
    size_t i = 0;
    while(i < sizeof(uint64_t) && *partialIVLen == 0) {
        if(partialIV[i] != 0) {
            *partialIVLen = sizeof(uint64_t) - i;
        }
        i++;
    }
    memmove(partialIV, partialIV+sizeof(uint64_t)-*partialIVLen, *partialIVLen);
}

static void oscore_internal_u64_from_partialIV(uint64_t * v, uint8_t const * partialIV, size_t partialIVLen) {
#ifdef LWM2M_BIG_ENDIAN
    memcpy(((uint8_t*)v)+sizeof(uint64_t)-partialIVLen, partialIV, partialIVLen);
#else
    ntworder((uint8_t*)v, (uint8_t*)partialIV, partialIVLen);
#endif
}

int oscore_message_encrypt(oscore_context_t * ctx, oscore_message_t * msg) {
    if(ctx == NULL || msg == NULL) {
        return -1;
    }
    if(msg->buffer == NULL) {
        return -1;
    }
    
    uint8_t piv[OSCORE_PARTIALIV_MAXLEN];
    memset(piv,0,OSCORE_PARTIALIV_MAXLEN);
    size_t piv_len = 0;
    oscore_security_context_t * sender = msg->recipient->sender;

    if(sender->senderSequenceNumber > OSCORE_SENDERSEQUENCENUMBER_MAX) {
        LOG("Sender sequence number out of range");
        return -1;
    }

    coap_packet_t coap_pkt;
    coap_packet_t oscore;
    bool isResponse = false;
    uint8_t oscore_code = COAP_POST;
    int ret = 0;
    oscore_option_itor_t itor;
    if(oscore_option_itor_init(&itor, msg->buffer, msg->length) != 0){
        LOG("Invalid CoAP message");
        return -1;
    }
    uint8_t coap_code = msg->buffer[1];
    uint8_t type = (msg->buffer[0] & 0x30)>>4;
    uint16_t msgId = 0;
    ntworder((uint8_t*)&msgId, msg->buffer + 2, 2);
    coap_init_message(&coap_pkt, type, coap_code, msgId);
    coap_init_message(&oscore, type, coap_code, msg->recipient->msgId++);
    uint8_t tokenLen = msg->buffer[0] & 0x0F;
    uint8_t * token = msg->buffer+4;
    coap_set_header_token(&oscore, token, tokenLen);
    oscore_request_mapping_t * receivedRequest = NULL;
    oscore_request_mapping_t * request = NULL;
    // todo add support to OBSERVE option

    if(coap_code != COAP_GET && coap_code != COAP_POST && coap_code != COAP_PUT && coap_code != COAP_DELETE){
        oscore_code = CHANGED_2_04;
        isResponse = true;
    }

    if(!isResponse || msg->generatePartialIV) { // partial IV must be calculated
        //if we find a request, we transmit a retransmission
        request = oscore_find_request(ctx->sentRequest, token, tokenLen, msg->recipient);
        memset(piv, 0, 8);
        oscore_internal_u64_to_partialIV(sender->senderSequenceNumber, piv, &(piv_len));
        if(sender->senderSequenceNumber == 0){
            piv_len = 1;
        }
    }
    if(isResponse) {
        receivedRequest = oscore_find_request(ctx->receivedRequest, token, tokenLen, msg->recipient);
        if(receivedRequest == NULL) {
            LOG("Could not find recipient");
            return OSCORE_COULD_NOT_FIND_RECIPIENT;
        }
        ctx->receivedRequest = oscore_remove_request(ctx->receivedRequest, receivedRequest);
    }
    
    uint8_t nonce[OSCORE_MAXNONCELEN];

    if(!isResponse || msg->generatePartialIV) { // use sender id
        ret = oscore_derive_nonce(sender->senderId, sender->senderIdLen, sender->commonIV, sender->nonceLen, piv, piv_len, nonce);
    }
    else { // use recipient id
        ret = oscore_derive_nonce(msg->recipient->recipientId, msg->recipient->recipientIdLen, sender->commonIV, sender->nonceLen, receivedRequest->partialIV, receivedRequest->partialIVLen, nonce);
    }
    
    if(ret < 0) {
        OSCORE_FREE(receivedRequest);
        return -1;
    }

    cose_aead_alg_t * aead = cose_aead_algorithm_find(&ctx->cose, sender->aeadAlgId);
    if(aead == NULL){
        OSCORE_FREE(receivedRequest);
        LOG("aead algorithm not defined");
        return -1;
    }
    
    if(aead->keyLen != sender->senderKeyLen || aead->nonceMin != sender->nonceLen) {
        OSCORE_FREE(receivedRequest);
        LOG("invalid security context with aead algorithm");
        return -1;
    }

    coap_set_status_code(&oscore, oscore_code);

    while((ret = oscore_option_itor_next(&itor)) == 1) {
        if(oscore_internal_is_EOption(itor.option)) {
            if(coap_parse_option(&coap_pkt, itor.option, (uint8_t*)itor.value, itor.valueLength)!= NO_ERROR) {
                coap_free_header(&oscore);
                coap_free_header(&coap_pkt);
                OSCORE_FREE(receivedRequest);
                LOG("Invalid CoAP option");
                return -1;
            }
        }
        else if(itor.option == COAP_OPTION_OSCORE) {
            coap_free_header(&oscore);
            coap_free_header(&coap_pkt);
            OSCORE_FREE(receivedRequest);
            LOG("OSCORE option in CoAP message found");
            return -1;
        }
        else if(coap_parse_option(&oscore, itor.option, (uint8_t*)itor.value, itor.valueLength) != NO_ERROR) {
            coap_free_header(&oscore);
            coap_free_header(&coap_pkt);
            OSCORE_FREE(receivedRequest);
            LOG("Invalid CoAP Option");
            return -1;
        }
    }

    if(ret != 0) {
        coap_free_header(&oscore);
        coap_free_header(&coap_pkt);
        OSCORE_FREE(receivedRequest);
        LOG("Invalid CoAP message");
        return -1;
    }

    int payloadLen = msg->length - (itor.beginOption + 1 - msg->buffer);
    if(payloadLen > 0){
        coap_set_payload(&coap_pkt, itor.beginOption + 1, payloadLen);
    }

    ret = coap_serialize_get_size(&coap_pkt);
    int sizeCoap = ret;

    if(isResponse) {
        ret = oscore_additional_authenticated_data_serialize(NULL, 0, sender->aeadAlgId, msg->recipient->recipientId, msg->recipient->recipientIdLen, receivedRequest->partialIV, receivedRequest->partialIVLen);
    }
    else {
        ret = oscore_additional_authenticated_data_serialize(NULL, 0, sender->aeadAlgId, sender->senderId, sender->senderIdLen, piv, piv_len);
    }
    
    
    if(ret <= 0) {
        coap_free_header(&oscore);
        coap_free_header(&coap_pkt);
        OSCORE_FREE(receivedRequest);
        LOG("Could not serialize AAD");
        return -1;
    }
    int aadLen = ret;
    uint8_t * aad = OSCORE_MALLOC(aadLen);
        
    if(aad == NULL) {
        coap_free_header(&oscore);
        coap_free_header(&coap_pkt);
        OSCORE_FREE(receivedRequest);
        LOG("Out of memory");
        return -1;
    }
    uint8_t * serializedCoap = OSCORE_MALLOC(sizeCoap);
    if(serializedCoap == NULL){
        coap_free_header(&oscore);
        coap_free_header(&coap_pkt);
        OSCORE_FREE(receivedRequest);
        LOG("Out of memory");
        OSCORE_FREE(aad);
        return -1;
    }

    if(isResponse) {
        aadLen = oscore_additional_authenticated_data_serialize(aad, aadLen, sender->aeadAlgId, msg->recipient->recipientId, msg->recipient->recipientIdLen, receivedRequest->partialIV, receivedRequest->partialIVLen);
        OSCORE_FREE(receivedRequest);
    }
    else {
        aadLen = oscore_additional_authenticated_data_serialize(aad, aadLen, sender->aeadAlgId, sender->senderId, sender->senderIdLen, piv, piv_len);
    }
    
    
    sizeCoap = coap_serialize_message(&coap_pkt, serializedCoap);
    coap_free_header(&coap_pkt);
    
    memmove(serializedCoap, serializedCoap+1, 1); // move code
    memmove(serializedCoap+1,serializedCoap+4, sizeCoap-4); // move options and payload
    sizeCoap = sizeCoap - 3;

    cose_aead_parameters_t parameters;
    parameters.plaintext = serializedCoap;
    parameters.plaintextLen = sizeCoap;
    parameters.key.key = (uint8_t*)sender->senderKey;
    parameters.key.keyLen = sender->senderKeyLen;
    parameters.nonce = nonce;
    parameters.nonceLen = sender->nonceLen;
    parameters.aadEncoded = aad;
    parameters.aadLen = aadLen;

    uint8_t * out = OSCORE_MALLOC(parameters.plaintextLen + aead->relatingCipherTextLen);
    if(out == NULL) {
        coap_free_header(&oscore);
        OSCORE_FREE(aad);
        OSCORE_FREE(serializedCoap);
        LOG("Out of memory");
        return -1;
    }

    if(aead->encrypt(&parameters, NULL, out) != COSE_OK){
        coap_free_header(&oscore);
        OSCORE_FREE(out);
        OSCORE_FREE(aad);
        OSCORE_FREE(serializedCoap);
        LOG("Could not encrypt message");
        return -1;
    }
    OSCORE_FREE(aad);
    OSCORE_FREE(serializedCoap);
    
    coap_set_payload(&oscore, out, parameters.plaintextLen + aead->relatingCipherTextLen);

    if(isResponse) {
        if(msg->generatePartialIV) {
            coap_set_header_oscore(&oscore, piv, piv_len, sender->idContext, sender->idContextLen, NULL, 0);
            sender->senderSequenceNumber++;
        }
        else{
            coap_set_header_oscore(&oscore, NULL, 0, NULL, 0, NULL, 0);
        }
        
    }
    else {
        uint8_t const * senderId = OSCORE_EMPTY_ENTRY;
        size_t senderIdLen = 0;
        if(sender->senderId != NULL && sender->senderIdLen > 0) {
            senderId = sender->senderId;
            senderIdLen = sender->senderIdLen;
        }
        coap_set_header_oscore(&oscore, piv, piv_len, sender->idContext, sender->idContextLen, senderId, senderIdLen);
        if(request != NULL) {
            request->timeout = time(NULL) + COAP_MAX_RTT;
        }
        sender->senderSequenceNumber++;
    }
    
    sizeCoap = coap_serialize_get_size(&oscore);

    uint8_t * oscore_out = OSCORE_MALLOC(sizeCoap);
    if(oscore_out == NULL){
        coap_free_header(&oscore);
        OSCORE_FREE(out);
        LOG("Ouf of memory");
        return -1;
    }
    sizeCoap = coap_serialize_message(&oscore, oscore_out);
    coap_free_header(&oscore);
    OSCORE_FREE(out);
    if(!isResponse && request == NULL) {
        oscore_request_mapping_t * mapping = (oscore_request_mapping_t*)OSCORE_MALLOC(sizeof(oscore_request_mapping_t));
        if(mapping == NULL){
            LOG("Out of memory");
            OSCORE_FREE(oscore_out);
            return -1;
        }
        mapping->recipient = msg->recipient;
        memcpy(mapping->partialIV, piv, piv_len);
        memcpy(mapping->token, token, tokenLen);
        mapping->partialIVLen = piv_len;
        mapping->tokenLen = tokenLen;
        mapping->timeout = time(NULL) + COAP_MAX_RTT;
        mapping->msgId = msgId; // save msgId used by coap
        mapping->next = ctx->sentRequest;
        ctx->sentRequest = mapping;
    }
    msg->buffer = oscore_out;
    msg->length = sizeCoap;
    return 0;
}


int oscore_add_security_ctx(oscore_context_t * ctx, oscore_common_context_t const * commonCtx, oscore_derived_context_t const * derivedCtx, oscore_security_context_t * security) {
    if(ctx == NULL || commonCtx == NULL || derivedCtx == NULL || security == NULL) {
        return -1;
    }

    memset(security, 0, sizeof(oscore_security_context_t));
    security->senderId = commonCtx->senderId;
    security->senderIdLen = commonCtx->senderIdLen;
    security->idContext = commonCtx->idContext;
    security->idContextLen = commonCtx->idContextLen;
    security->aeadAlgId = &commonCtx->aeadAlgId;
    security->senderKey = derivedCtx->senderKey;
    security->senderKeyLen = derivedCtx->keyLen;
    security->commonIV = derivedCtx->commonIV;
    security->nonceLen = derivedCtx->nonceLen;

    // add to list
    security->next = ctx->security;
    ctx->security = security;

    return 0;
}

int oscore_add_recipient_ctx(oscore_context_t * ctx, oscore_common_context_t const * commonCtx, oscore_derived_context_t const * derivedCtx, oscore_security_context_t * security, oscore_recipient_t * recipient) {
    if(ctx == NULL || commonCtx == NULL || derivedCtx == NULL || security == NULL || recipient == NULL) {
        return -1;
    }

    recipient->sender = security;
    recipient->recipientId = commonCtx->recipientId;
    recipient->recipientIdLen = commonCtx->recipientIdLen;
    recipient->recipientKey = derivedCtx->recipientKey;
    recipient->recipientKeyLen = derivedCtx->keyLen;
    recipient->msgId = time(NULL) + rand();
    recipient->next = ctx->recipient;
    ctx->recipient = recipient;

    return 0;
}

int oscore_is_oscore_message(uint8_t const * buffer, size_t length) {
    if((buffer[0] & 0x40) != 0x40){
        return -2; //invalid CoAP Version
    }
    oscore_option_itor_t itor;
    if(oscore_option_itor_init(&itor, (uint8_t*)buffer, length) != 0){
        LOG("Received invalid CoAP Header");
        return -1;
    }
    int ret = 0;
    while((ret = oscore_option_itor_next(&itor)) == 1) {
        if(itor.option == COAP_OPTION_OSCORE) {
            return 1;
        }
    }
    if(ret == -1) {
        LOG("Invalid CoAP format");
        return -1;
    }
    return ret;
}

static int oscore_internal_remove_EOptions(uint8_t * input, size_t const length) {
    oscore_option_itor_t itor;
    if(oscore_option_itor_init(&itor, input, length) != 0){
        LOG("Received invalid CoAP Header");
        return -1;
    }
    int ret = 0;
    int subLength = 0;
    coap_option_t prevOption = 0;
    oscore_option_itor_t nextOption;
    memset(&nextOption, 0, sizeof(oscore_option_itor_t));

    while((ret = oscore_option_itor_next(&itor)) == 1) {
        
        if(oscore_internal_is_EOption(itor.option)) {
            // must be removed
            memcpy(&nextOption, &itor, sizeof(oscore_option_itor_t));
            int r = oscore_option_itor_next(&nextOption);
            if(r == -1) {
                LOG("Invalid format");
                return -1;
            }
            if(r == 0)  {// end reached
                memmove(itor.beginOption, nextOption.beginOption, length - (nextOption.beginOption - input));
                itor.nextOption = itor.beginOption;
            }
            else {
                uint32_t delta = nextOption.option - prevOption;
                size_t written = coap_set_option_header(delta, nextOption.valueLength, itor.beginOption);
                memmove(itor.beginOption + written, nextOption.value, (input + length) - nextOption.value);
                itor.nextOption = itor.beginOption;// + written + nextOption.valueLength;
                itor.option = prevOption;
            }
            
            subLength = subLength + (nextOption.beginOption - itor.beginOption);
            
        }
        prevOption = itor.option;
    }
    if(ret == -1) {
        LOG("Invalid CoAP format");
        return -1;
    }
    return length - subLength;
}

static bool oscore_internal_verify_replaywindow(oscore_security_context_t * security, uint64_t sequenceNumber) {
    if(sequenceNumber + OSCORE_REPLAY_WINDOW_SIZE <= security->highestValidatedSequenceNumber) {
        return false;
    }
    if(sequenceNumber < security->highestValidatedSequenceNumber) {
        uint64_t diff = security->highestValidatedSequenceNumber - sequenceNumber;
        if((security->replayWindow & (1 << (diff - 1))) != 0){
            return false;
        }
    }
    return true;
}

static void oscore_internal_update_replaywindow(oscore_security_context_t * security, uint64_t sequenceNumber) {
    if(security->highestValidatedSequenceNumber < sequenceNumber) {
        uint64_t diff = sequenceNumber - security->highestValidatedSequenceNumber;
        security->replayWindow = security->replayWindow << diff;
        if(security->highestValidatedSequenceNumber + OSCORE_REPLAY_WINDOW_SIZE > sequenceNumber) {
            security->replayWindow |= (1 << (diff-1));
        }
        security->highestValidatedSequenceNumber = sequenceNumber;
    }
    else {
        uint64_t diff = security->highestValidatedSequenceNumber - sequenceNumber;
        security->replayWindow |= (1<<diff);
    }
}

oscore_recipient_t * oscore_find_recipient(oscore_recipient_t * begin, uint8_t const * kid, size_t kidLen, uint8_t const * idContext, size_t idContextLen) {
    oscore_recipient_t * kidMatch = NULL;
    while(begin != NULL){
        if(kidLen == begin->recipientIdLen && memcmp(kid, begin->recipientId, kidLen) == 0) {
            if(idContext == NULL && kidMatch == NULL) { // there was no idContext supplied, it could be a match
                kidMatch = begin;
            }
            if(idContextLen == begin->sender->idContextLen && memcmp(idContext, begin->sender->idContext, idContextLen) == 0) {
                // return exact match
                return begin;
            }
        }

        begin = begin->next;
    }
    return kidMatch;
}

int oscore_message_decrypt(oscore_context_t * ctx, oscore_message_t * msg) {
    if(ctx == NULL || msg == NULL  || msg->buffer == NULL || msg->length < 4) {
        return -1;
    }
    // remove all outer options which are class E
    int newlength = oscore_internal_remove_EOptions(msg->buffer, msg->length);
    if(newlength <= 0) {
        LOG("Could not parse received oscore message");
        return -1;
    }
    coap_packet_t packet;
    coap_status_t coapRet = coap_parse_message(&packet, msg->buffer, newlength);
    if(coapRet != NO_ERROR) {
        LOG("Could not parse message");
        return -1;
    }
    bool isResponse = false;
    if(packet.code == CHANGED_2_04) {
        isResponse = true;
    }
    // remove option of message
    REMOVE_OPTION(&packet, COAP_OPTION_OSCORE);
    
    // get recipient data of oscore option value (when request) or of token (when response)
    // get recipient context based on id and id context
    uint8_t partialIVArr[8];
    cose_aead_alg_t * aead = NULL;
    oscore_recipient_t * recipient = NULL;
    oscore_request_mapping_t * request = NULL;
    uint64_t sequenceNumber = 0;
    uint8_t const * partialIV = NULL;
    size_t partialIVLen = 0;
    if(!isResponse) {
        if(packet.oscore_partialIV == NULL || packet.oscore_partialIVLen == 0) {
            LOG("No partial IV encoded in oscore request");
            return OSCORE_DECOMPRESS_FAILED;
        }
        recipient = oscore_find_recipient(ctx->recipient, packet.oscore_kid, packet.oscore_kidLen, packet.oscore_kidContext, packet.oscore_kidContextLen);
        // todo verify multiple recipients, because there could be multiple context with same kid
        if(recipient == NULL) {
            coap_free_header(&packet);
            coap_error_message = "Security context not found";
            LOG("Recipient context not available");
            return OSCORE_COULD_NOT_FIND_RECIPIENT;
        }
    }
    else {
        request = oscore_find_request(ctx->sentRequest, packet.token, packet.token_len, msg->recipient);
        if(request == NULL){
            LOG("No request was send");
            coap_free_header(&packet);
            return OSCORE_COULD_NOT_FIND_RECIPIENT;
        }
        recipient = request->recipient;
        if(packet.oscore_partialIVLen != 0) {
            partialIV = packet.oscore_partialIV;
            partialIVLen = packet.oscore_partialIVLen;
        }
        else {
            partialIV = request->partialIV;
            partialIVLen = request->partialIVLen;
        }
    }

    if(packet.oscore_partialIVLen != 0) {
        memset(partialIVArr, 0, 8);
        memcpy(partialIVArr, packet.oscore_partialIV, packet.oscore_partialIVLen);
        oscore_internal_u64_from_partialIV(&sequenceNumber, packet.oscore_partialIV, packet.oscore_partialIVLen);
        // verify replay window
        if(!oscore_internal_verify_replaywindow(recipient->sender, sequenceNumber)) {
            LOG("Replay detected");
            coap_error_message = "Replay detected";
            coap_free_header(&packet);
            return OSCORE_REPLAY_DETECTED;
        }
        partialIV = partialIVArr;
        partialIVLen = packet.oscore_partialIVLen;
    }

    msg->recipient = recipient;

    aead = cose_aead_algorithm_find(&ctx->cose, recipient->sender->aeadAlgId);

    if(aead == NULL) {
        LOG("Unsupported aead algorithm");
        coap_free_header(&packet);
        return -1;
    }

    if(aead->keyLen != recipient->recipientKeyLen || aead->nonceMin != recipient->sender->nonceLen) {
        LOG("Keylen or Noncelen are not equal");
        coap_free_header(&packet);
        return -1;
    }
    
    // compute nonce
    uint8_t nonce[OSCORE_MAXNONCELEN];
    int ret = 0;
    if(packet.oscore_partialIVLen != 0) {
        ret = oscore_derive_nonce(recipient->recipientId, recipient->recipientIdLen, recipient->sender->commonIV, recipient->sender->nonceLen, partialIV, partialIVLen, nonce);
    }
    else {
        ret = oscore_derive_nonce(recipient->sender->senderId, recipient->sender->senderIdLen, recipient->sender->commonIV, recipient->sender->nonceLen, partialIV, partialIVLen, nonce);
    }
    

    if(ret < 0){
        LOG("Unexpected error");
        coap_free_header(&packet);
        return -1;
    }

    // compose AAD
    int aadLen = 0;
    uint8_t * aad = NULL;
    if(!isResponse) {
        aadLen = oscore_additional_authenticated_data_get_size(recipient->sender->aeadAlgId, recipient->recipientId, recipient->recipientIdLen, packet.oscore_partialIV, packet.oscore_partialIVLen);
    }
    else {
        aadLen = oscore_additional_authenticated_data_get_size(recipient->sender->aeadAlgId, recipient->sender->senderId, recipient->sender->senderIdLen, request->partialIV, request->partialIVLen);
    }


    if(aadLen <= 0) {
        coap_free_header(&packet);
        return -1;
    }
    aad = OSCORE_MALLOC(aadLen);
    if(aad == NULL) {
        LOG("Out of memory");
        coap_free_header(&packet);
        return -1;
    }

    if(!isResponse) {
        aadLen = oscore_additional_authenticated_data_serialize(aad, aadLen, recipient->sender->aeadAlgId, recipient->recipientId, recipient->recipientIdLen, packet.oscore_partialIV, packet.oscore_partialIVLen);
    }
    else {
        aadLen = oscore_additional_authenticated_data_serialize(aad, aadLen, recipient->sender->aeadAlgId, recipient->sender->senderId, recipient->sender->senderIdLen, request->partialIV, request->partialIVLen);
    }

    // decrypt
    cose_aead_parameters_t par;
    memset(&par, 0, sizeof(cose_aead_parameters_t));
    par.plaintext = OSCORE_MALLOC(packet.payload_len - aead->relatingCipherTextLen);
    if(par.plaintext == NULL){
        OSCORE_FREE(aad);
        coap_free_header(&packet);
        LOG("Out of memory");
        return -1;
    }
    par.plaintextLen = packet.payload_len - aead->relatingCipherTextLen;
    par.key.key = (uint8_t*)recipient->recipientKey;
    par.key.keyLen = recipient->recipientKeyLen;
    
    par.nonce = nonce;
    par.nonceLen = aead->nonceMin;
    par.aadEncoded = aad;
    par.aadLen = aadLen;

    cose_error_t cose_ret = aead->decrypt(&par, NULL, packet.payload, packet.payload_len);

    OSCORE_FREE(aad);
    if(cose_ret != COSE_OK){
        coap_error_message = "Decryption failed";
        OSCORE_FREE(par.plaintext);
        coap_free_header(&packet);
        return OSCORE_VERIFICATION_FAILED;
    }

    if(isResponse) {
        ctx->sentRequest = oscore_remove_request(ctx->sentRequest, request);
        // set back correct message id
        packet.mid = request->msgId;
        OSCORE_FREE(request);
    }
    

    // update replay window
    if(packet.oscore_partialIVLen != 0) {
        oscore_internal_update_replaywindow(recipient->sender, sequenceNumber);
    }
    
    // update coap msg with decrypted information
    packet.code = par.plaintext[0];
    oscore_option_itor_t itor; //oscore_option_itor_init cant be used as it verfies complete coap header
    memset(&itor, 0, sizeof(oscore_option_itor_t));
    itor.nextOption = par.plaintext + 1;
    itor.buffer = par.plaintext + 1;
    itor.length = par.plaintextLen - 1;

    while((ret = oscore_option_itor_next(&itor)) == 1) {
        if(coap_parse_option(&packet, itor.option, (uint8_t*)itor.value, itor.valueLength) != NO_ERROR) {
            LOG("Could not parse options");
            coap_free_header(&packet);
            OSCORE_FREE(par.plaintext);
            return -1;
        }
    }

    if(ret != 0) {
        LOG("Invalid format in CoAP message");
        coap_free_header(&packet);
        OSCORE_FREE(par.plaintext);
        return -1;
    }

    if(itor.nextOption < par.plaintext + par.plaintextLen) {
        packet.payload = itor.nextOption + 1;
        packet.payload_len = par.plaintext + par.plaintextLen - packet.payload;
    }
    else{
        packet.payload = NULL;
        packet.payload_len = 0;
    }

    if(!isResponse) {
        request = (oscore_request_mapping_t*)OSCORE_MALLOC(sizeof(oscore_request_mapping_t));
        if(request == NULL) {
            OSCORE_FREE(par.plaintext);
            coap_free_header(&packet);
            LOG("Out of memory");
            return -1;
        }
        request->recipient = msg->recipient;
        request->timeout = time(NULL) + COAP_MAX_RTT;
        memcpy(request->token, packet.token, packet.token_len);
        request->tokenLen = packet.token_len;
        memcpy(request->partialIV, partialIV, partialIVLen);
        request->partialIVLen = partialIVLen;
        request->next = ctx->receivedRequest;
        ctx->receivedRequest = request;
    }

    size_t coap_size = coap_serialize_get_size(&packet);
    msg->buffer = OSCORE_MALLOC(coap_size);
    if(msg->buffer == NULL){
        OSCORE_FREE(par.plaintext);
        coap_free_header(&packet);
        LOG("Out of memory");
        return -1;
    }
    msg->length = coap_serialize_message(&packet, msg->buffer);
    OSCORE_FREE(par.plaintext);
    coap_free_header(&packet);

    return 0;
}


oscore_request_mapping_t * oscore_find_request(oscore_request_mapping_t * begin, uint8_t * token, uint8_t tokenLen, oscore_recipient_t const *recipient) {
    if(begin == NULL){
        return NULL;
    }
    while(begin != NULL){
        if(begin->recipient == recipient) {
            if(tokenLen == 0 && begin->tokenLen == 0){
                return begin;
            }
            if(begin->tokenLen == tokenLen && memcmp(begin->token, token, tokenLen) == 0){
                return begin;
            }
        }
        
        
        begin = begin->next;
    }
    return NULL;
}

oscore_request_mapping_t * oscore_remove_request(oscore_request_mapping_t * begin, oscore_request_mapping_t * del) {
    if(begin == NULL || del == NULL){
        return begin;
    }
    if(begin == del) {
        oscore_request_mapping_t * next = begin->next;
        return next;
    }
    oscore_request_mapping_t * itor = begin;
    while(itor != NULL && itor->next != del) {
        itor = itor->next;
    }
    if(itor->next == del) {
        itor->next = del->next;
    }
    return begin;
}