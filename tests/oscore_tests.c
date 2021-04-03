#include "tests.h"
#include "CUnit/Basic.h"
#include "er-coap-13/er-coap-13.h"


#define CU_ASSERT_ARRAY_EQUAL(actual, expected, length) \
    if(actual != NULL && expected != NULL) { \
        for(size_t i = 0; i < length; i++) { CU_ASSERT_EQUAL(actual[i], expected[i]);} \
    } \
    else { \
        CU_ASSERT_PTR_EQUAL(actual, expected); \
    }

static void test_oscore_cant_add_PartialIV_longer_5() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t partialIV[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    CU_ASSERT_FALSE(coap_set_header_oscore(&packet, partialIV, 6, NULL, 0, NULL, 0));
    CU_ASSERT_PTR_NULL(packet.oscore_partialIV);
    CU_ASSERT_PTR_NULL(packet.oscore_kidContext);
    CU_ASSERT_PTR_NULL(packet.oscore_kid);
    CU_ASSERT_EQUAL(packet.oscore_partialIVLen, 0);
    CU_ASSERT_EQUAL(packet.oscore_kidContextLen, 0);
    CU_ASSERT_EQUAL(packet.oscore_kidLen, 0);
}

static void test_oscore_cant_add_values_longer_255(){
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t arr[1] = {0x01};


    CU_ASSERT_FALSE(coap_set_header_oscore(&packet, arr, 5, arr, 149, arr, 100));
    CU_ASSERT_PTR_NULL(packet.oscore_partialIV);
    CU_ASSERT_PTR_NULL(packet.oscore_kidContext);
    CU_ASSERT_PTR_NULL(packet.oscore_kid);
    CU_ASSERT_EQUAL(packet.oscore_partialIVLen, 0);
    CU_ASSERT_EQUAL(packet.oscore_kidContextLen, 0);
    CU_ASSERT_EQUAL(packet.oscore_kidLen, 0);
}

static void test_oscore_can_add_PartialIV_length_5() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t partialIV[5] = {0x01, 0x02, 0x03, 0x04, 0x05};

    CU_ASSERT_TRUE(coap_set_header_oscore(&packet, partialIV, 5, NULL, 0, NULL, 0));
    CU_ASSERT_PTR_EQUAL(partialIV, packet.oscore_partialIV);
    CU_ASSERT_PTR_NULL(packet.oscore_kidContext);
    CU_ASSERT_PTR_NULL(packet.oscore_kid);
    CU_ASSERT_EQUAL(packet.oscore_partialIVLen, 5);
    CU_ASSERT_EQUAL(packet.oscore_kidContextLen, 0);
    CU_ASSERT_EQUAL(packet.oscore_kidLen, 0);
}

static void test_oscore_can_set_header() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const partialIV[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t const kidContext[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t const kid[3] = {0x01, 0x02, 0x03};

    CU_ASSERT_TRUE(coap_set_header_oscore(&packet, partialIV, 5, kidContext, 4, kid, 3));
    CU_ASSERT_PTR_EQUAL(partialIV, packet.oscore_partialIV);
    CU_ASSERT_PTR_EQUAL(kidContext, packet.oscore_kidContext);
    CU_ASSERT_PTR_EQUAL(kid, packet.oscore_kid);
    CU_ASSERT_EQUAL(packet.oscore_partialIVLen, 5);
    CU_ASSERT_EQUAL(packet.oscore_kidContextLen, 4);
    CU_ASSERT_EQUAL(packet.oscore_kidLen, 3);
}

static void test_oscore_can_get_headers() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const partialIV[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t const kidContext[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t const kid[3] = {0x01, 0x02, 0x03};

    coap_set_header_oscore(&packet, partialIV, 5, kidContext, 4, kid, 3);

    uint8_t const * partialIVGet = NULL;
    uint8_t partialIVLen = 0;
    uint8_t const * kidContextGet = NULL;
    uint8_t kidContextLen = 0;
    uint8_t const * kidGet = NULL;
    uint8_t kidLen = 0;

    CU_ASSERT_TRUE(coap_get_header_oscore(&packet, &partialIVGet, &partialIVLen, &kidContextGet, &kidContextLen, &kidGet, &kidLen));
    CU_ASSERT_PTR_EQUAL(partialIV, partialIVGet);
    CU_ASSERT_PTR_EQUAL(kidContext, kidContextGet);
    CU_ASSERT_PTR_EQUAL(kid, kidGet);
    CU_ASSERT_EQUAL(partialIVLen, 5);
    CU_ASSERT_EQUAL(kidContextLen, 4);
    CU_ASSERT_EQUAL(kidLen, 3);
}

static void test_oscore_serialize_option_partialIV_correctly() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const partialIV[5] = {0x01, 0x02, 0x03, 0x04, 0x05};

    coap_set_header_oscore(&packet, partialIV, 5, NULL, 0, NULL, 0);
    uint8_t message[11];
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x96,
                                        0x05, 0x01, 0x02, 0x03,
                                        0x04, 0x05};

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), 11);

    for(unsigned int i = 0; i < sizeof(message); i++) {
        CU_ASSERT_EQUAL(message[i], expectedmessage[i]);
    }
}

static void test_oscore_serialize_option_kidContext_correctly() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const kidContext[5] = {0x01, 0x02, 0x03, 0x04, 0x05};

    coap_set_header_oscore(&packet, NULL, 0, kidContext, 5, NULL, 0);
    uint8_t message[12];
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x97,
                                        0x08, 0x05, 0x01, 0x02,
                                        0x03, 0x04, 0x05};

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), 12);

    for(unsigned int i = 0; i < sizeof(message); i++) {
        CU_ASSERT_EQUAL(message[i], expectedmessage[i]);
    }
}

static void test_oscore_serialize_option_kid_correctly() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const kid[5] = {0x01, 0x02, 0x03, 0x04, 0x05};

    coap_set_header_oscore(&packet, NULL, 0, NULL, 0, kid, 5);
    uint8_t message[11];
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x96,
                                        0x10, 0x01, 0x02, 0x03,
                                        0x04, 0x05};

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), 11);

    for(unsigned int i = 0; i < sizeof(message); i++) {
        CU_ASSERT_EQUAL(message[i], expectedmessage[i]);
    }
}

// RFC8613 6.3.Examples of Compressed COSE Objects Example 4 -> leads to empty option value
static void test_oscore_serialize_option_with_empty_value() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    coap_set_header_oscore(&packet, NULL, 0, NULL, 0, NULL, 0);
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x90};

    uint8_t message[5];
    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), 5);

    CU_ASSERT_ARRAY_EQUAL(message, expectedmessage, sizeof(expectedmessage));
}

static void test_oscore_serialize_option_correctly() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const partialIV[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t const kidContext[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t const kid[3] = {0x01, 0x02, 0x03};

    coap_set_header_oscore(&packet, partialIV, 5, kidContext, 4, kid, 3);

    uint8_t message[20];
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x9D, 0x01,
                                        0x1D, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x04,
                                        0x01, 0x02, 0x03, 0x04,
                                        0x01, 0x02, 0x03};

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), 20);

    for(unsigned int i = 0; i < sizeof(message); i++) {
        CU_ASSERT_EQUAL(message[i], expectedmessage[i]);
    }
}

static void test_oscore_parse_option_with_s0_works() {
    uint8_t const oscoreOption[] = {0x08, 0x00};

    coap_packet_t packet;
    CU_ASSERT_EQUAL(coap_parse_oscore_option(&packet,oscoreOption, 2), 0);

}

static void test_oscore_parse_option_with_invalid_encoding_returns_error() {
    uint8_t const oscoreOption[] = {0x08, 0x05, 0x01, 0x02, 0x03, 0x04};

    coap_packet_t packet;
    CU_ASSERT_EQUAL(coap_parse_oscore_option(&packet, oscoreOption, sizeof(oscoreOption)), BAD_OPTION_4_02);
}

static void test_oscore_can_parse_option_with_partialIV() {
    uint8_t message[] =  {0x40, COAP_GET, 0x12, 0x34,
                                0x96,
                                0x05, 0x01, 0x02, 0x03,
                                0x04, 0x05};
    coap_packet_t packet;
    CU_ASSERT_EQUAL(coap_parse_message(&packet,message,sizeof(message)), 0);
    
    uint8_t const * partialIVGet = NULL;
    uint8_t partialIVLen = 0;

    CU_ASSERT_TRUE(coap_get_header_oscore(&packet, &partialIVGet, &partialIVLen, NULL, NULL, NULL, NULL));

    uint8_t const expectedPartialIV[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CU_ASSERT_EQUAL(partialIVLen, sizeof(expectedPartialIV));
    CU_ASSERT_ARRAY_EQUAL(partialIVGet, expectedPartialIV, partialIVLen);
}

static void test_oscore_can_parse_option_with_kidContext() {
    uint8_t message[] =  {0x40, COAP_GET, 0x12, 0x34,
                                0x97,
                                0x08, 0x05, 0x01, 0x02,
                                0x03, 0x04, 0x05};
    coap_packet_t packet;
    CU_ASSERT_EQUAL(coap_parse_message(&packet,message,sizeof(message)), 0);

    uint8_t const * kidContextGet = NULL;
    uint8_t kidContextLen = 0;

    CU_ASSERT_TRUE(coap_get_header_oscore(&packet, NULL, NULL, &kidContextGet, &kidContextLen, NULL, NULL));

    uint8_t const expectedkidContext[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CU_ASSERT_EQUAL(kidContextLen, sizeof(expectedkidContext));
    CU_ASSERT_ARRAY_EQUAL(kidContextGet, expectedkidContext, kidContextLen);
}

static void test_oscore_can_parse_option_with_kid() {
    uint8_t message[] =  {0x40, COAP_GET, 0x12, 0x34,
                                0x96,
                                0x10, 0x01, 0x02, 0x03,
                                0x04, 0x05};

    coap_packet_t packet;
    CU_ASSERT_EQUAL(coap_parse_message(&packet,message,sizeof(message)), 0);

    uint8_t const * kidGet = NULL;
    uint8_t kidLen = 0;

    CU_ASSERT_TRUE(coap_get_header_oscore(&packet, NULL, NULL, NULL, NULL, &kidGet, &kidLen));

    uint8_t const expectedkid[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CU_ASSERT_EQUAL(kidLen, sizeof(expectedkid));
    CU_ASSERT_ARRAY_EQUAL(kidGet, expectedkid, kidLen);
}

static void test_oscore_can_parse_complete_option() {
    uint8_t message[] =  {0x40, COAP_GET, 0x12, 0x34,
                                0x9D, 0x01,
                                0x1D, 0x01, 0x02, 0x03, 0x04, 0x05,
                                0x04,
                                0x01, 0x02, 0x03, 0x04,
                                0x01, 0x02, 0x03};

    coap_packet_t packet;
    CU_ASSERT_EQUAL(coap_parse_message(&packet,message,sizeof(message)), 0);

    uint8_t const * partialIVGet = NULL;
    uint8_t partialIVLen = 0;
    uint8_t const * kidContextGet = NULL;
    uint8_t kidContextLen = 0;
    uint8_t const * kidGet = NULL;
    uint8_t kidLen = 0;

    CU_ASSERT_TRUE(coap_get_header_oscore(&packet, &partialIVGet, &partialIVLen, &kidContextGet, &kidContextLen, &kidGet, &kidLen));

    uint8_t const expectedPartialIV[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CU_ASSERT_EQUAL(partialIVLen, sizeof(expectedPartialIV));
    CU_ASSERT_ARRAY_EQUAL(partialIVGet, expectedPartialIV, partialIVLen);

    uint8_t const expectedkidContext[] = {0x01, 0x02, 0x03, 0x04};
    CU_ASSERT_EQUAL(kidContextLen, sizeof(expectedkidContext));
    CU_ASSERT_ARRAY_EQUAL(kidContextGet, expectedkidContext, kidContextLen);

    uint8_t const expectedkid[] = {0x01, 0x02, 0x03};
    CU_ASSERT_EQUAL(kidLen, sizeof(expectedkid));
    CU_ASSERT_ARRAY_EQUAL(kidGet, expectedkid, kidLen);
}

static void test_oscore_serialize_get_size_returns_correct() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const partialIV[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t const kidContext[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t const kid[3] = {0x01, 0x02, 0x03};

    coap_set_header_oscore(&packet, partialIV, 5, kidContext, 4, kid, 3);

    CU_ASSERT_EQUAL(coap_serialize_get_size(&packet), 23);
}

// Example of RFC8613 5.4.Additional Authenticated Data
static void test_oscore_get_size_aad_works() {
    cn_cbor alg;
    memset(&alg, 0, sizeof(cn_cbor));
    alg.type = CN_CBOR_UINT;
    alg.v.uint = OSCORE_ALGO_AES_CCM_16_64_128;
    uint8_t kid[] = {0x00};
    uint8_t partialIV[] = {0x25};

    CU_ASSERT_EQUAL(oscore_additional_authenticated_data_get_size(&alg, kid, sizeof(kid), partialIV, sizeof(partialIV)), 21);
}

static void test_oscore_serialize_aad_works() {
    cn_cbor alg;
    memset(&alg, 0, sizeof(cn_cbor));
    alg.type = CN_CBOR_UINT;
    alg.v.uint = OSCORE_ALGO_AES_CCM_16_64_128;
    uint8_t kid[] = {0x00};
    uint8_t partialIV[] = {0x25};

    uint8_t const expectedAAD[] = {
        0x83, 0x68, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70,
        0x74, 0x30, 0x40, 0x49, 0x85, 0x01, 0x81, 0x0a,
        0x41, 0x00, 0x41, 0x25, 0x40
    };

    uint8_t aad[sizeof(expectedAAD)];

    CU_ASSERT_EQUAL(oscore_additional_authenticated_data_serialize(aad, sizeof(aad), &alg, kid, sizeof(kid), partialIV, sizeof(partialIV)), 21);
    CU_ASSERT_ARRAY_EQUAL(aad, expectedAAD, sizeof(expectedAAD));
}

static struct TestTable table[] = {
        // CoAP Option tests
        { "[OPTION] cant add Partial IV longer than 5 bytes", test_oscore_cant_add_PartialIV_longer_5 },
        { "[OPTION] cant add values which lead to option value greater 255", test_oscore_cant_add_values_longer_255 },
        { "[OPTION] can add Partial IV with length 5", test_oscore_can_add_PartialIV_length_5 },
        { "[OPTION] can set all headers", test_oscore_can_set_header },
        { "[OPTION] can get all headers", test_oscore_can_get_headers },
        { "[OPTION] serializes partial IV correctly in option", test_oscore_serialize_option_partialIV_correctly },
        { "[OPTION] serializes kidContext correctly in option", test_oscore_serialize_option_kidContext_correctly },
        { "[OPTION] serializes kid correctly in option", test_oscore_serialize_option_kid_correctly },
        { "[OPTION] serializes option with no information to empty value", test_oscore_serialize_option_with_empty_value},
        { "[OPTION] serializes option correctly", test_oscore_serialize_option_correctly },
        { "[OPTION] parse option with s=0 works", test_oscore_parse_option_with_s0_works },
        { "[OPTION] parse option with invalid encoding returns error", test_oscore_parse_option_with_invalid_encoding_returns_error },
        { "[OPTION] can parse option with partialIV", test_oscore_can_parse_option_with_partialIV },
        { "[OPTION] can parse option with kidContext", test_oscore_can_parse_option_with_kidContext },
        { "[OPTION] can parse option with kid", test_oscore_can_parse_option_with_kid },
        { "[OPTION] can parse complete option", test_oscore_can_parse_complete_option },
        { "[OPTION] coap message size is calculated correctly", test_oscore_serialize_get_size_returns_correct },

        // additional authenticated data tests
        { "[AAD] AAD size is calculated correctly", test_oscore_get_size_aad_works },
        { "[AAD] AAD serialize works", test_oscore_serialize_aad_works },
        { NULL, NULL },
};

CU_ErrorCode create_oscore_suit()
{
   CU_pSuite pSuite = NULL;

   pSuite = CU_add_suite("Suite_OSCORE", NULL, NULL);
   if (NULL == pSuite) {
      return CU_get_error();
   }

   return add_tests(pSuite, table);
}