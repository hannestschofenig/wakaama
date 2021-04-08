#include "lwm2mclient.h"
#include <string.h>

typedef struct _oscore_instance_ {
    struct _oscore_instance_ * next;
    uint16_t instanceId;
    oscore_common_context_t * common;
    oscore_derived_context_t * derived;
    oscore_recipient_t * recipient;
} oscore_instance_t;

static uint8_t prv_get_value(lwm2m_data_t * dataP,
                             oscore_instance_t * targetP)
{
    switch (dataP->id) {
        case LWM2M_OSCORE_RECIPIENT_ID_ID:
            lwm2m_data_encode_opaque(targetP->common->recipientId, targetP->common->recipientIdLen, dataP);
            return COAP_205_CONTENT;
        break;

        case LWM2M_OSCORE_ID_CONTEXT_ID:
            lwm2m_data_encode_opaque(targetP->common->idContext, targetP->common->idContextLen, dataP);
            return COAP_205_CONTENT;
        break;
        default:
            return COAP_404_NOT_FOUND;
    }
}

static uint8_t prv_oscore_read(uint16_t instanceId,
                                 int * numDataP,
                                 lwm2m_data_t ** dataArrayP,
                                 lwm2m_object_t * objectP)
{
    oscore_instance_t * targetP;
    uint8_t result;
    int i;
    targetP = (oscore_instance_t *)lwm2m_list_find(objectP->instanceList, instanceId);
    if (NULL == targetP) return COAP_404_NOT_FOUND;

    if (*numDataP == 0)
    {
        uint16_t resList[] = {
                                LWM2M_OSCORE_MASTER_SECRET_ID,
                                LWM2M_OSCORE_SENDER_ID_ID,
                                LWM2M_OSCORE_RECIPIENT_ID_ID,
                                LWM2M_OSCORE_AEAD_ALGORITHM_ID,
                                LWM2M_OSCORE_HMAC_ALGORITHM_ID,
                                LWM2M_OSCORE_MASTER_SALT_ID,
                                LWM2M_OSCORE_ID_CONTEXT_ID,
                             };
        int nbRes = sizeof(resList)/sizeof(uint16_t);

        *dataArrayP = lwm2m_data_new(nbRes);
        if (*dataArrayP == NULL) return COAP_500_INTERNAL_SERVER_ERROR;
        *numDataP = nbRes;
        for (i = 0 ; i < nbRes ; i++)
        {
            (*dataArrayP)[i].id = resList[i];
        }
    }

    i = 0;
    do
    {
        if ((*dataArrayP)[i].type == LWM2M_TYPE_MULTIPLE_RESOURCE)
        {
            result = COAP_404_NOT_FOUND;
        }
        else
        {
            result = prv_get_value((*dataArrayP) + i, targetP);
        }
        i++;
    } while (i < *numDataP && result == COAP_205_CONTENT);

    return result;

}

lwm2m_object_t * get_oscore_object() {
    lwm2m_object_t * oscore = (lwm2m_object_t*)lwm2m_malloc(sizeof(lwm2m_object_t));

    if(oscore != NULL) {
        memset(oscore,0,sizeof(lwm2m_object_t));
        oscore->objID = LWM2M_OSCORE_OBJECT_ID;
        oscore->readFunc = prv_oscore_read;
    }
    return oscore;
}

int oscore_object_add_instance(lwm2m_object_t * objectP, lwm2m_context_t * ctx, oscore_common_context_t * common) {
    oscore_instance_t * instance = (oscore_instance_t*)lwm2m_malloc(sizeof(oscore_instance_t));
    if(instance == NULL) {
        return 0;
    }
    oscore_derived_context_t * derivedCtx = (oscore_derived_context_t*)lwm2m_malloc(sizeof(oscore_derived_context_t));
    if(derivedCtx == NULL) {
        lwm2m_free(instance);
        return 0;
    }
    oscore_recipient_t * recipientCtx = (oscore_recipient_t*)lwm2m_malloc(sizeof(oscore_recipient_t));
    if(recipientCtx == NULL){
        lwm2m_free(instance);
        lwm2m_free(derivedCtx);
        return 0;
    }
    oscore_security_context_t * securityCtx = (oscore_security_context_t*)lwm2m_malloc(sizeof(oscore_security_context_t));
    if(recipientCtx == NULL){
        lwm2m_free(instance);
        lwm2m_free(derivedCtx);
        lwm2m_free(recipientCtx);
        return 0;
    }
    instance->common = common;
    instance->derived = derivedCtx;
    instance->recipient = recipientCtx;

    if(oscore_derive_context(&ctx->oscore, common, derivedCtx) != 0) {
        lwm2m_free(instance);
        lwm2m_free(derivedCtx);
        lwm2m_free(recipientCtx);
        lwm2m_free(securityCtx);
        return 0;
    }

    if(oscore_add_security_ctx(&ctx->oscore, common, derivedCtx, securityCtx) != 0){
        lwm2m_free(instance);
        lwm2m_free(derivedCtx);
        lwm2m_free(recipientCtx);
        lwm2m_free(securityCtx);
        return 0;
    }
    if(oscore_add_recipient_ctx(&ctx->oscore, common, derivedCtx, securityCtx, recipientCtx) != 0) {
        lwm2m_free(instance);
        lwm2m_free(derivedCtx);
        lwm2m_free(recipientCtx);
        lwm2m_free(securityCtx);
        return 0;
    }

    objectP->instanceList = LWM2M_LIST_ADD(objectP->instanceList, instance);
    
    return 0;
}