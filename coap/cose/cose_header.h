#ifndef COSE_HEADER_H_
#define COSE_HEADER_H_

#include <cn-cbor/cn-cbor.h>
#include "cose/cose.h"

typedef struct cose_header {
    cn_cbor * label;
    cn_cbor * value;
} cose_header_t;

typedef enum {
    COSE_HEADER_PROTECTED = 0,
    COSE_HEADER_UNPROTECTED = 1
}cose_header_type_t;


#define COSE_HEADER_LABEL_ALG 1
#define COSE_HEADER_LABEL_CRIT 2
#define COSE_HEADER_LABEL_CONTENT_TYPE 3
#define COSE_HEADER_LABEL_KID 4
#define COSE_HEADER_LABEL_IV 5
#define COSE_HEADER_LABEL_PARTIAL_IV 6
#define COSE_HEADER_LABEL_COUNTER_SIGNATURE 7


void cose_header_map_init(cose_header_map_t * headermap);
cose_error_t cose_header_map_free(cose_context_t* ctx, cose_header_map_t * headermap);
cose_error_t cose_header_map_add(cose_header_map_t * headermap, cose_header_t * header, cose_header_type_t type);
//always tries to find lbl in protected bucket first
cn_cbor * cose_header_map_find(cose_header_map_t * map, cn_cbor * lbl);
cn_cbor * cose_header_map_find_str(cose_header_map_t * map, char const * str);
cn_cbor * cose_header_map_find_int(cose_header_map_t * map, int64_t i);
cn_cbor * cose_header_map_find_uint(cose_header_map_t * map, uint64_t i);
bool cose_header_map_valid(cose_header_map_t * headermap);

//serializes protected bucket into a bytestring
//prot: empty cbor object
cose_error_t cose_header_map_serialize(cose_context_t* ctx, cose_header_map_t * headermap, cn_cbor * prot);


cn_cbor * cose_header_find(cn_cbor * bucket, cn_cbor * lbl);
cn_cbor * cose_header_find_str(cn_cbor * bucket, char const * str);
cn_cbor * cose_header_find_int(cn_cbor * bucket, int64_t i);
cn_cbor * cose_header_find_uint(cn_cbor * bucket, uint64_t i);



#endif