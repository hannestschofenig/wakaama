#include "oscore/oscore.h"
#include "cose/cose_util.h"
#include "er-coap-13/er-coap-13.h"
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
        coap_pkt->oscore_kidContextLen = value[1+coap_pkt->oscore_partialIVLen];
        kidLen -= (coap_pkt->oscore_kidContextLen + 1);
        maxLength += (coap_pkt->oscore_kidContextLen + 1);
    }
    if((value[0] & 0x08)) { // kid available
        if(kidLen < 0) {
            return BAD_OPTION_4_02;
        }
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
    if(commonCtx->idContext == NULL){
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
    COAP_OPTION_PROXY_URI,
    COAP_OPTION_PROXY_SCHEME
};

static bool oscore_internal_is_EOption(coap_option_t op) {
    for(size_t i = 0; i < sizeof(OSCORE_U_OPTIONS); i++) {
        if(op == OSCORE_U_OPTIONS[i]) {
            return false;
        }
    }
    return true;
}

static coap_option_t oscore_internal_get_next_EOption(coap_packet_t * packet) {
    for(size_t i = 0; i < sizeof(OSCORE_E_OPTIONS); i++) {
        if(IS_OPTION(packet, OSCORE_E_OPTIONS[i])) {
            return OSCORE_E_OPTIONS[i];
        }
    }
    return OPTION_MAX_VALUE;
}

static int oscore_move_EOptions(coap_packet_t * unprotected, coap_packet_t * protectedMsg) {
    coap_option_t option;
    while((option = oscore_internal_get_next_EOption(unprotected)) != OPTION_MAX_VALUE) {
        REMOVE_OPTION(unprotected, option);
        switch(option) {
            case COAP_OPTION_URI_PATH:
                protectedMsg->uri_path = unprotected->uri_path;
                unprotected->uri_path = NULL;
                SET_OPTION(protectedMsg, option);
            break;

            default:
            // TODO handle all unknown options as protected options..
            // maybe add a function to coap library to create a list of all options...
            LOG("Unsupported option");
        }
    }   

    return 0;
}

int oscore_message_encrypt(oscore_context_t * ctx, oscore_sender_context_t * sender, oscore_message_t * msg) {
    if(ctx == NULL || sender == NULL || msg == NULL) {
        return -1;
    }
    if(msg->partialIVLen > OSCORE_PARTIALIV_MAXLEN) {
        return -1;
    }
    uint8_t requestPIV[OSCORE_PARTIALIV_MAXLEN];
    size_t requestPIVLen = msg->partialIVLen;
    memcpy(requestPIV, msg->partialIV, msg->partialIVLen);

    coap_packet_t * oscore = (coap_packet_t *)msg->packet;
    coap_packet_t coap_pkt;
    bool isResponse = false;
    uint8_t code = COAP_POST;

    if(oscore->code != COAP_GET && oscore->code != COAP_POST && oscore->code != COAP_PUT && oscore->code != COAP_DELETE){
        code = CHANGED_2_04;
        isResponse = true;
    }

    if(!isResponse || msg->generatePartialIV) { // partial IV must be calculated
        if(sender->senderSequenceNumber > OSCORE_SENDERSEQUENCENUMBER_MAX) {
            LOG("Sender sequence number out of range");
            return -1;
        }
        memset(msg->partialIV, 0, 8);
        ntworder(msg->partialIV, &sender->senderSequenceNumber, 8);
        for(int i = 7; i >= 0; i--) {
            if(msg->partialIV[i] != 0) {
                msg->partialIVLen = 8 - i;
                i = -1;
            }
        }
        memmove(msg->partialIV, msg->partialIV+8-msg->partialIVLen, msg->partialIVLen);
        if(sender->senderSequenceNumber == 0){
            msg->partialIVLen = 1;
        }
    }
    
    uint8_t nonce[OSCORE_MAXNONCELEN];
    int ret = 0;

    if(!isResponse || msg->generatePartialIV) { // use sender id
        ret = oscore_derive_nonce(sender->senderId, sender->senderIdLen, sender->commonIV, sender->nonceLen, msg->partialIV, msg->partialIVLen, nonce);
    }
    else { // use recipient id
        ret = oscore_derive_nonce(msg->id, msg->idLen, sender->commonIV, sender->nonceLen, msg->partialIV, msg->partialIVLen, nonce);
    }
    
    if(ret < 0) {
        return -1;
    }

    cose_aead_alg_t * aead = cose_aead_algorithm_find(&ctx->cose, sender->aeadAlgId);
    if(aead == NULL){
        LOG("aead algorithm not defined");
        return -1;
    }
    
    if(aead->keyLen != sender->senderKeyLen || aead->nonceMin != sender->nonceLen) {
        LOG("invalid security context with aead algorithm");
        return -1;
    }

    coap_init_message(&coap_pkt, oscore->type, oscore->code, oscore->mid);
    coap_set_payload(&coap_pkt, oscore->payload, oscore->payload_len);

    coap_set_status_code(oscore, code);

    if(oscore_move_EOptions(oscore, &coap_pkt) != 0) {
        LOG("Could not move options");
        return -1;
    }

    ret = coap_serialize_get_size(&coap_pkt);
    if(ret <= 0){
        LOG("Could not calculate size of coap message");
        return -1;
    }
    int sizeCoap = ret;

    if(isResponse) {
        ret = oscore_additional_authenticated_data_serialize(NULL, 0, sender->aeadAlgId, msg->id, msg->idLen, requestPIV, requestPIVLen);
    }
    else {
        ret = oscore_additional_authenticated_data_serialize(NULL, 0, sender->aeadAlgId, sender->senderId, sender->senderIdLen, msg->partialIV, msg->partialIVLen);
    }
    
    
    if(ret <= 0) {
        LOG("Could not serialize AAD");
        return -1;
    }
    int aadLen = ret;
    uint8_t * aad = OSCORE_MALLOC(aadLen);
        
    if(aad == NULL) {
        LOG("Out of memory");
        return -1;
    }
    uint8_t * serializedCoap = OSCORE_MALLOC(sizeCoap);
    if(serializedCoap == NULL){
        LOG("Out of memory");
        OSCORE_FREE(aad);
        return -1;
    }

    if(isResponse) {
        aadLen = oscore_additional_authenticated_data_serialize(aad, aadLen, sender->aeadAlgId, msg->id, msg->idLen, requestPIV, requestPIVLen);
    }
    else {
        aadLen = oscore_additional_authenticated_data_serialize(aad, aadLen, sender->aeadAlgId, sender->senderId, sender->senderIdLen, msg->partialIV, msg->partialIVLen);
    }
    
    sizeCoap = coap_serialize_message(&coap_pkt, serializedCoap);
    
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
        OSCORE_FREE(aad);
        OSCORE_FREE(serializedCoap);
        LOG("Out of memory");
        return -1;
    }

    if(aead->encrypt(&parameters, NULL, out) != COSE_OK){
        OSCORE_FREE(aad);
        OSCORE_FREE(serializedCoap);
        LOG("Could not encrypt message");
        return -1;
    }
    OSCORE_FREE(aad);
    OSCORE_FREE(serializedCoap);
    
    coap_set_payload(oscore, out, parameters.plaintextLen + aead->relatingCipherTextLen);

    if(isResponse) {
        if(msg->generatePartialIV) {
            coap_set_header_oscore(oscore, msg->partialIV, msg->partialIVLen, sender->idContext, sender->idContextLen, NULL, 0);
            sender->senderSequenceNumber++;
        }
        else{
            coap_set_header_oscore(oscore, NULL, 0, NULL, 0, NULL, 0);
        }
        
    }
    else {
        uint8_t const * senderId = OSCORE_EMPTY_ENTRY;
        size_t senderIdLen = 0;
        if(sender->senderId != NULL && sender->senderIdLen > 0) {
            senderId = sender->senderId;
            senderIdLen = sender->senderIdLen;
        }
        coap_set_header_oscore(oscore, msg->partialIV, msg->partialIVLen, sender->idContext, sender->idContextLen, senderId, senderIdLen);
        sender->senderSequenceNumber++;
    }
    
    
    return 0;
}

int oscore_add_recipient(oscore_context_t * ctx, oscore_common_context_t const * commonCtx, oscore_derived_context_t const * derivedCtx, oscore_recipient_context_t * recipient) {
    if(ctx == NULL || commonCtx == NULL || derivedCtx == NULL || recipient == NULL) {
        return -1;
    }
    memset(recipient, 0, sizeof(oscore_recipient_context_t));
    recipient->recipientId = commonCtx->recipientId;
    recipient->recipientIdLen = commonCtx->recipientIdLen;
    recipient->idContext = commonCtx->idContext;
    recipient->idContextLen = commonCtx->idContextLen;
    recipient->aeadAlgId = &commonCtx->aeadAlgId;
    recipient->recipientKey = derivedCtx->recipientKey;
    recipient->recipientKeyLen = derivedCtx->keyLen;
    recipient->commonIV = derivedCtx->commonIV;
    recipient->nonceLen = derivedCtx->nonceLen;

    // add to list
    recipient->next = ctx->recipient;
    ctx->recipient = recipient;

    return 0;
}

oscore_recipient_context_t * oscore_find_recipient(oscore_recipient_context_t * begin, uint8_t const * id, size_t idLen, uint8_t const * idContext, size_t idContextLen) {
    oscore_recipient_context_t * matchId = NULL;
    while(begin != NULL) {
        if(begin->recipientIdLen == idLen){
            if(memcmp(begin->recipientId, id, idLen) == 0) {
                if(matchId == NULL) {
                    matchId = begin;
                }
                if(begin->idContextLen == idContextLen && memcmp(begin->idContext, idContext, idContextLen) ==0) { // complete match
                    return begin;
                }
            }
        }
        begin = begin->next;
    }
    // if no complete match was found try with security context with matching id
    return matchId;
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
    int tokenlength = buffer[0] & 0x0F;
    if(tokenlength > 8) {
        return -1;
    }
    if(length < 4 + tokenlength) {
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
    if(itor->beginOption - itor->buffer >= itor->length) {
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
    uint16_t * v = NULL;
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
    itor->valueLength = optionLength;
    itor->value = pos;
    itor->nextOption = pos + optionLength;

    return 1;
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

/*extern size_t
coap_serialize_int_option(unsigned int number, unsigned int current_number, uint8_t *buffer, uint32_t value);*/

static int oscore_internal_remove_EOptions(uint8_t * input, size_t const length) {
    oscore_option_itor_t itor;
    if(oscore_option_itor_init(&itor, input, length) != 0){
        LOG("Received invalid CoAP Header");
        return -1;
    }
    int ret = 0;
    coap_option_t option = 0;
    oscore_option_itor_t lastOption;

    while((ret = oscore_option_itor_next(&itor)) == 1) {
        uint32_t delta = itor.option - option;
        if(oscore_internal_is_EOption(itor.option)) {
            memmove(itor.nextOption, itor.beginOption, length - (itor.beginOption - input));
        }
        option = itor.option;
    }
    if(ret == -1) {
        LOG("Invalid CoAP format");
        return -1;
    }
    return 0;
}

int oscore_message_decrypt(oscore_context_t * ctx, oscore_message_t * msg, uint8_t * input, size_t length) {

    // remove all outer options which are class E
    int newlength = oscore_internal_remove_EOptions(input, length);
    // get recipient data of oscore option value

    // get recipient context based on id and id context

    // verify replay window

    // compose AAD

    // compute nonce

    // decrypt

    // update replay window

    // update coap msg with decrypted information
    return -1;
}