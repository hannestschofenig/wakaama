#ifndef OSCORE_H_
#define OSCORE_H_
#include <stdint.h>
#include "cn-cbor/cn-cbor.h"

#define OSCORE_PARTIALIV_MAXLEN 5
#define OSCORE_OPTION_VALUE_MAXLEN 255

#define OSCORE_ALGO_AES_CCM_16_64_128 0x0A

#define COAP_SERIALIZE_OSCORE_OPTION(number, text)      \
    if (IS_OPTION(coap_pkt, number)) \
    { \
      uint8_t hdr = (coap_pkt->oscore_partialIVLen & 0x07); \
      uint8_t len = hdr + 1; \
      if(coap_pkt->oscore_kidContextLen > 0) { hdr |= 0x08; len+= 1 + coap_pkt->oscore_kidContextLen;}\
      if(coap_pkt->oscore_kidLen > 0) {hdr |= 0x10; len+=coap_pkt->oscore_kidLen;}\
      if(hdr == 0){ option += coap_set_option_header(number - current_number, 0, option);} \
      else { \
          option += coap_set_option_header(number - current_number, len, option); \
          *option = hdr; \
          option++; \
          for(size_t i = 0; i < coap_pkt->oscore_partialIVLen; i++) { \
              *option = coap_pkt->oscore_partialIV[i]; \
              option++; \
          } \
          if(coap_pkt->oscore_kidContextLen > 0) { \
              *option = coap_pkt->oscore_kidContextLen; \
              option++; \
          } \
          for(size_t i = 0; i < coap_pkt->oscore_kidContextLen; i++) { \
              *option = coap_pkt->oscore_kidContext[i]; \
              option++; \
          } \
          for(size_t i = 0; i < coap_pkt->oscore_kidLen; i++) { \
              *option = coap_pkt->oscore_kid[i]; \
              option++; \
          } \
          current_number = number; \
      } \
    }


int coap_set_header_oscore(void * packet, uint8_t const * partialIV, uint8_t partialIVLen, uint8_t const * kidcontext, uint8_t kidcontextLen, uint8_t const * kid, uint8_t kidLen);
int coap_get_header_oscore(void * packet, uint8_t const ** partialIV, uint8_t * partialIVLen, uint8_t const ** kidcontext, uint8_t * kidcontextLen, uint8_t const ** kid, uint8_t *kidLen);
int coap_parse_oscore_option(void * packet, uint8_t const * value, uint32_t const optionLength);

// additional data
// as there are currently no Class I options, this is not supported by current implementation
// algorithms could be an array of valid COSE algorithms identifer or just one algorithm identifier
int oscore_additional_authenticated_data_get_size(cn_cbor const * algorithms, uint8_t const * kid, uint8_t const kidLen, uint8_t const * partialIV, uint8_t const partialIVLen);

// use oscore_additional_authenticated_data_get_size to precalculate size
int oscore_additional_authenticated_data_serialize(uint8_t * buffer, size_t const length, cn_cbor const * algorithms, uint8_t const * kid, uint8_t const kidLen, uint8_t const * partialIV, uint8_t const partialIVLen);

#endif