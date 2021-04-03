# Provides COAP_SOURCES_DIR and COAP_HEADERS_DIR variables.
# Add LWM2M_WITH_LOGS to compile definitions to enable logging.

set(COAP_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})
set(COAP_HEADERS_DIR ${CMAKE_CURRENT_LIST_DIR})

set(COAP_SOURCES
    ${COAP_SOURCES_DIR}/transaction.c
    ${COAP_SOURCES_DIR}/block.c
    ${COAP_SOURCES_DIR}/er-coap-13/er-coap-13.c)

set(COSE_SOURCES
    ${COAP_SOURCES_DIR}/cose/cose.c
    ${COAP_SOURCES_DIR}/cose/cose_encrypt0.c
    ${COAP_SOURCES_DIR}/cose/cose_header.c
    ${COAP_SOURCES_DIR}/cose/cose_util.c
    ${COAP_SOURCES_DIR}/cose/backend/cose_mbedtls.c
)

set(OSCORE_SOURCES
    ${COAP_SOURCES_DIR}/oscore/oscore.c
    ${COAP_SOURCES_DIR}/oscore/backend/oscore_mbedtls.c
    ${COSE_SOURCES}
)