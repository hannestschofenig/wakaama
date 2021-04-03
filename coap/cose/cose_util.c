#include "cose/cose_util.h"
#include <assert.h>
#include <string.h>

#define MAX_RECURSION_DEPTH 3

static bool cbor_is_same_internal(cn_cbor const * value1, cn_cbor const * value2, int call) {
    // to prevent stack overflows
    if(call >= MAX_RECURSION_DEPTH) {
        return -1;
    }
    if(value1==value2){
        return 1;
    }
    if(value1->type != value2->type){
        return 0;
    }
    assert(value1->type != CN_CBOR_BYTES_CHUNKED && value1->type != CN_CBOR_TEXT_CHUNKED); //currently not supported
    switch(value1->type) {
        case CN_CBOR_UINT:
            return value1->v.uint == value2->v.uint;
        break;

        case CN_CBOR_INT:
            return value1->v.sint == value2->v.sint;
        break;

        case CN_CBOR_BYTES:
        case CN_CBOR_TEXT:
            if(value1->length != value2->length) {
                return 0;
            }
            if(value1->length == 0) { //both are zero -> equal
                return 1;
            }
            assert(value1->v.bytes != NULL && value2->v.bytes != NULL);
            if(memcmp(value1->v.bytes, value2->v.bytes, value1->length) == 0){
                return 1;
            }
            return 0;
        break;

        case CN_CBOR_MAP:
        case CN_CBOR_ARRAY: {
            if(value1->length != value2->length) {
                return 0;
            }
            if(value1->length == 0) { //both are zero -> equal
                return 1;
            }
            cn_cbor * v1 = value1->first_child;
            cn_cbor * v2 = value2->first_child;
            while(v1 != NULL && v2 != NULL) {
                int ret = cbor_is_same_internal(v1,v2,call+1);
                if(ret == 0){
                    v1 = v1->next;
                    v2 = v2->next;
                }
                else {
                    return ret;
                }
            }
            if(v1 != v2) { // one of both is not NULL
                return 0;
            }
            return 1;
        }
        break;

        case CN_CBOR_TAG:
            if(value1->v.sint != value2->v.sint) {
                return 0;
            }
            assert(value1->first_child != NULL && value2->first_child != NULL);
            return cbor_is_same_internal(value1->first_child,value2->first_child,call+1);
            
        break;

        case CN_CBOR_SIMPLE:
            if(value1->v.uint != value2->v.uint){
                return 0;
            }
            return 1;
        break;

#ifndef CBOR_NO_FLOAT
        case CN_CBOR_DOUBLE:
            if(value1->v.dbl != value2->v.dbl) {
                return 0;
            }
            return 1;
        break;
        case CN_CBOR_FLOAT:
            if(value1->v.f != value2->v.f) {
                return 0;
            }
            return 1;
        break;
#endif
    }
    return -1;
}

bool cbor_is_same(cn_cbor const * value1, cn_cbor const * value2) {
    return cbor_is_same_internal(value1, value2, 0);
}


bool cose_algorithm_valid_identifier(cn_cbor const * id) {
    if(id == NULL) {
        return false;
    }
    if(id->type == CN_CBOR_UINT) {
        return true;
    }
    if(id->type == CN_CBOR_INT) {
        return true;
    }
    if(id->type == CN_CBOR_TEXT && id->length > 0) {
        return true;
    }
    return false;
}

bool cbor_remove_from_array(cn_cbor * arr, cn_cbor * val) {
    if(arr == NULL || val == NULL || arr->type != CN_CBOR_ARRAY) {
        return false;
    }

    cn_cbor * elem = arr->first_child;
    if(arr->first_child == val){
        arr->first_child = val->next;
        arr->length--;
        if(arr->last_child == val){
            arr->last_child = NULL;
        }
        val->parent = NULL;
        val->next = NULL;
        return true;
    }

    while(elem != NULL && elem->next != val){
        elem = elem->next;
    }
    if(elem != NULL){
        elem->next = val->next;
        if(arr->last_child == val) {
            arr->last_child = elem;
        }
        arr->length--;
        val->parent = NULL;
        val->next = NULL;
        return true;
    }
    
    return false;
}