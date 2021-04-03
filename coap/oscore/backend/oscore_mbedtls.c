#include "oscore/oscore.h"
#include "mbedtls/hkdf.h"
#include <string.h>

#define MBEDTLS_ALGORITHMS 1

/*mbedtls_sha256_info*/
/*mbedtls_md_type_t -> MBEDTLS_MD_SHA256*/

extern const mbedtls_md_info_t mbedtls_sha256_info;

static int mbedtls_hkdf_SHA256_extract(uint8_t const * salt, size_t saltLen, uint8_t const * ikm, size_t ikmLen, uint8_t * okm) {
    return mbedtls_hkdf_extract(&mbedtls_sha256_info, salt, saltLen, ikm, ikmLen, okm);
}

static int mbedtls_hkdf_SHA256_expand(uint8_t const * prk, size_t prkLen, uint8_t const * info, size_t infoLen, uint8_t * okm, size_t okmLen) {
    return mbedtls_hkdf_expand(&mbedtls_sha256_info, prk, prkLen, info, infoLen, okm, okmLen);
}

static oscore_hkdf_alg_t mbedtls_hkdfs[MBEDTLS_ALGORITHMS];
static bool initialized = false;

void oscore_backend_init(oscore_context_t * ctx) {
    if(!initialized) {
        memset(mbedtls_hkdfs, 0, sizeof(oscore_hkdf_alg_t)*MBEDTLS_ALGORITHMS);
        mbedtls_hkdfs[0].id.type = CN_CBOR_INT;
        mbedtls_hkdfs[0].id.v.sint = COSE_ALGO_HKDF_SHA_256;
        mbedtls_hkdfs[0].size = 32;
        mbedtls_hkdfs[0].extract = mbedtls_hkdf_SHA256_extract;
        mbedtls_hkdfs[0].expand = mbedtls_hkdf_SHA256_expand;
        initialized = true;
    }
    for(size_t i = 0; i < MBEDTLS_ALGORITHMS; i++) {
        oscore_hkdf_algorithm_add(ctx, mbedtls_hkdfs + i);
    }
}

void oscore_backend_free(oscore_context_t * ctx) {
    for(size_t i = 0; i < MBEDTLS_ALGORITHMS; i++) {
        oscore_hkdf_algorithm_rm(ctx, &mbedtls_hkdfs[i].id, NULL);
    }
}