#include "cose/cose_header.h"
#include "cose/cose_util.h"
#include <assert.h>
#include <string.h>


static int cose_valid_label(cn_cbor * label) {
    if(label == NULL){
        return 0;
    }
    if(label->type == CN_CBOR_UINT) {
        return 1;
    }
    if(label->type == CN_CBOR_INT) {
        return 1;
    }
    if(label->type == CN_CBOR_TEXT) {
        return 1;
    }
    return 0;
}

static int cose_header_valid_label(cose_header_t * header) {
    if(header->label->type == CN_CBOR_UINT) {
        return 1;
    }
    if(header->label->type == CN_CBOR_INT) {
        return 1;
    }
    if(header->label->type == CN_CBOR_TEXT) {
        return 1;
    }
    return 0;
}

static int cose_header_map_has_label_uint(cose_header_map_t * map, uint64_t lbl) {
    if(cose_header_find_uint(&map->prot, lbl) != NULL) {
        return 1;
    }
    if(cose_header_find_uint(&map->unprot, lbl) != NULL) {
        return 1;
    }
    return 0;
}

static int cose_header_map_has_label(cose_header_map_t * map, cn_cbor * lbl) {
    if(cose_header_find(&map->prot, lbl) != NULL) {
        return 1;
    }
    if(cose_header_find(&map->unprot, lbl) != NULL) {
        return 1;
    }
    return 0;
}

static void cose_bucket_add_header(cn_cbor * bucket, cose_header_t * header) {
    if(bucket == NULL) return;
    cn_cbor_map_put(bucket, header->label, header->value, NULL);
}

static int cose_bucket_can_be_added_to_unprotected(cn_cbor * lbl) {
    if(lbl->type == CN_CBOR_UINT) {
        if(lbl->v.uint == COSE_HEADER_LABEL_CRIT) {
            return 0;
        }
    }
    return 1;
}

static bool cose_header_map_inited(cose_header_map_t * headermap) {
    if(headermap->prot.type != CN_CBOR_MAP) {
        return 0;
    }
    if(headermap->unprot.type != CN_CBOR_MAP) {
        return 0;
    }
    return 1;
}

void cose_header_map_init(cose_header_map_t * headermap) {
    if(headermap == NULL){
        return;
    }
    if(cose_header_map_inited(headermap)){
        return;
    }
    memset(headermap, 0, sizeof(cose_header_map_t));
    headermap->prot.type = CN_CBOR_MAP;
    headermap->prot.flags |= CN_CBOR_FL_COUNT | CN_CBOR_FL_EXT_SELF;
    headermap->unprot.type = CN_CBOR_MAP;
    headermap->unprot.flags |= CN_CBOR_FL_COUNT | CN_CBOR_FL_EXT_SELF;
}

cose_error_t cose_header_map_free(cose_context_t* ctx, cose_header_map_t * headermap) {
    if(cose_initialized(ctx) != COSE_OK){
        LOG("COSE context is needed to free header map");
        return COSE_INVALID_PARAM;
    }
    if(headermap == NULL){
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_inited(headermap)){
        return COSE_OK;
    }
    CBOR_CONTEXT_INIT(ctx)

    cn_cbor_free(&headermap->prot, CBOR_CONTEXT_INSERT);
    cn_cbor_free(&headermap->unprot, CBOR_CONTEXT_INSERT);
    memset(headermap, 0, sizeof(cose_header_map_t));
    return COSE_OK;
}

cn_cbor * cose_header_map_find(cose_header_map_t * map, cn_cbor * lbl) {
    if(map==NULL){
        return NULL;
    }
    if(!cose_header_map_valid(map)){
        return NULL;
    }
    cn_cbor * ret = cose_header_find(&map->prot, lbl);
    if(ret == NULL){
        ret = cose_header_find(&map->unprot, lbl);
    }
    return ret;
}

cn_cbor * cose_header_map_find_str(cose_header_map_t * map, char const * str) {
    cn_cbor lbl;
    memset(&lbl, 0, sizeof(cn_cbor));
    lbl.type = CN_CBOR_TEXT;
    lbl.v.str = str;
    return cose_header_map_find(map, &lbl);
}

cn_cbor * cose_header_map_find_int(cose_header_map_t * map, int64_t i) {
    cn_cbor lbl;
    memset(&lbl, 0, sizeof(cn_cbor));
    lbl.type = CN_CBOR_INT;
    lbl.v.sint = i;
    return cose_header_map_find(map, &lbl);
}

cn_cbor * cose_header_map_find_uint(cose_header_map_t * map, uint64_t i) {
    cn_cbor lbl;
    memset(&lbl, 0, sizeof(cn_cbor));
    lbl.type = CN_CBOR_UINT;
    lbl.v.uint = i;
    return cose_header_map_find(map, &lbl);
}

cose_error_t cose_header_map_add(cose_header_map_t * map, cose_header_t * header, cose_header_type_t type) {
    if(map == NULL || header == NULL || header->label == NULL || header->value == NULL) {
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_inited(map)){
        LOG("Headermap must be initialized before usage.");
        return COSE_INVALID_PARAM;
    }

    if(cose_header_valid_label(header) == 0){
        LOG("Tried to add invalid label to headermap");
        return COSE_INVALID_PARAM;
    }
    
    if(cose_header_map_has_label(map, header->label) == 1) {
        LOG("Header should not be twice in a any bucket");
        return COSE_ALREADY_AVAILABLE;
    }

    if(type == COSE_HEADER_PROTECTED) {
        cose_bucket_add_header(&map->prot, header);
    }
    else {
        if(cose_bucket_can_be_added_to_unprotected(header->label) == 0){
            LOG("Cant add this header to unprotected bucket");
            return COSE_INVALID_PARAM;
        }
        cose_bucket_add_header(&map->unprot, header);
    }
    return COSE_OK;
}

cn_cbor * cose_header_find(cn_cbor * begin, cn_cbor * lbl) {
    if(begin == NULL) {
        return NULL;
    }
    if(begin->type != CN_CBOR_MAP) {
        return NULL;
    }
    if(begin->first_child == NULL){
        return NULL;
    }
    begin = begin->first_child;
    while(begin != NULL) {
        if(cbor_is_same(begin, lbl)) {
            return begin->next; //map always uses two cbor elements (label->value)
        }
        begin = begin->next;
        if(begin == NULL) { //map always uses two cbor elements
            return NULL;
        }
        begin = begin->next;
    }
    return NULL;
}

cn_cbor * cose_header_find_str(cn_cbor * begin, char const * str) {
    cn_cbor lbl;
    memset(&lbl, 0, sizeof(cn_cbor));
    lbl.type = CN_CBOR_TEXT;
    lbl.v.str = str;
    return cose_header_find(begin, &lbl);
}

cn_cbor * cose_header_find_int(cn_cbor * begin, int64_t i) {
    cn_cbor lbl;
    memset(&lbl, 0, sizeof(cn_cbor));
    lbl.type = CN_CBOR_INT;
    lbl.v.sint = i;
    return cose_header_find(begin, &lbl);
}

cn_cbor * cose_header_find_uint(cn_cbor * begin, uint64_t i) {
    cn_cbor lbl;
    memset(&lbl, 0, sizeof(cn_cbor));
    lbl.type = CN_CBOR_UINT;
    lbl.v.uint = i;
    return cose_header_find(begin, &lbl);
}

bool cose_header_map_valid(cose_header_map_t * headermap) {
    if(headermap == NULL) {
        return false;
    }

    //verify no header is placed in twice in map
    cn_cbor * itor = headermap->unprot.first_child;

    if(headermap->unprot.type != CN_CBOR_MAP || headermap->unprot.type != CN_CBOR_MAP) {
        return false;
    }

    while(itor != NULL) {
        if(cose_valid_label(itor) != 1) {
            return false;
        }
        if(cose_header_find(&headermap->prot, itor) != NULL) { // same label in both maps
            return false;
        }
        if(cose_bucket_can_be_added_to_unprotected(itor) == 0){ // a label is placed in unprotected bucket which is not allowed there
            return false;
        }
        itor = itor->next; 
        if(itor == NULL) { //map always uses two cbor elements
            return false;
        }
        itor = itor->next;
    }

    itor = headermap->prot.first_child;
    while(itor != NULL) {
        if(cose_valid_label(itor) != 1) {
            return false;
        }
        itor = itor->next; 
        if(itor == NULL) { //map always uses two cbor elements
            return false;
        }
        itor = itor->next;
    }


    // it is now allowed to place IV and Partial IV in same bucket
    if(cose_header_map_has_label_uint(headermap, COSE_HEADER_LABEL_IV) == 1 && cose_header_map_has_label_uint(headermap, COSE_HEADER_LABEL_PARTIAL_IV) == 1) {
        return false;
    }

    return true;
}

cose_error_t cose_header_map_serialize(cose_context_t* ctx, cose_header_map_t * headermap, cn_cbor * prot) {
    if(prot == NULL){
        return COSE_INVALID_PARAM;
    }
    if(cose_initialized(ctx) != COSE_OK){
        return COSE_INVALID_PARAM;
    }
    if(!cose_header_map_valid(headermap)){
        return COSE_INVALID_PARAM;
    }

    ssize_t ret = 0;
    if(headermap->prot.first_child != NULL){
        ret = cn_cbor_encoder_write(NULL, 0, 0, &headermap->prot);
    }

    if(ret > 0) {
        memset(prot, 0, sizeof(cn_cbor));
        prot->type = CN_CBOR_BYTES;
        uint8_t * buf = COSE_CALLOC(ctx, ret);
        if(buf == NULL){
            return COSE_OUT_OF_MEMORY;
        }
        ret = cn_cbor_encoder_write(buf, 0, ret, &headermap->prot);
        if(ret > 0){
            prot->v.bytes = buf;
            prot->length = ret;
            return COSE_OK;
        }
        COSE_FREEF(ctx, buf);
        return COSE_UNDEFINED_CBOR_ERROR;
    }
    else if(ret == 0){ // no elements in map
        memset(prot, 0, sizeof(cn_cbor));
        prot->type = CN_CBOR_BYTES;
        return COSE_OK;
    }

    return COSE_UNDEFINED_CBOR_ERROR;
}