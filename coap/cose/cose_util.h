#ifndef COSE_UTIL_H_
#define COSE_UTIL_H_

#include "cn-cbor/cn-cbor.h"
#include "cose.h"

bool cbor_is_same(cn_cbor const * value1, cn_cbor const * value2);
bool cbor_remove_from_array(cn_cbor * arr, cn_cbor * val);
bool cose_algorithm_valid_identifier(cn_cbor const * id);

#ifdef COSE_DEBUG
    #define LOG(STR) cose_printf("[%s : %d] " STR "\r\n", __func__ , __LINE__)
    #define LOG_ARG(FMT, ...) cose_printf("[%s : %d] " FMT "\r\n", __func__ , __LINE__ , __VA_ARGS__)
#else
    #define LOG(STR)
    #define LOG_ARG(FMT, ...)
#endif

#define CBOR_CONTEXT_INIT(ctx) cn_cbor_context cborctx; cborctx.context = (ctx)->userContext; cborctx.calloc_func = (ctx)->calloc_func; cborctx.free_func = (ctx)->free_func;

#define CBOR_CONTEXT_INSERT &cborctx

#define COSE_CALLOC(ctx, bytes)  (ctx)->calloc_func(bytes, 1, (ctx)->userContext)
#define COSE_FREEF(ctx, ptr)  (ctx)->free_func(ptr, (ctx)->userContext)

#endif