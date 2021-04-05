#include "tests.h"
#include "CUnit/Basic.h"
#include "er-coap-13/er-coap-13.h"
#include "liblwm2m.h"


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
                                        0x10, 0x05, 0x01, 0x02,
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
                                        0x08, 0x01, 0x02, 0x03,
                                        0x04, 0x05};

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), 11);

    for(unsigned int i = 0; i < sizeof(message); i++) {
        CU_ASSERT_EQUAL(message[i], expectedmessage[i]);
    }
}

// RFC8613 6.3.Examples of Compressed COSE Objects Example 1
static void test_oscore_option_example1() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const kid[] = {
        0x25
    };
    uint8_t const partialIV[] = {
        0x05
    };
    coap_set_header_oscore(&packet, partialIV, sizeof(partialIV), NULL, 0, kid, sizeof(kid));

    
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x93,
                                        0x09, 0x05, 0x25};
    uint8_t message[sizeof(expectedmessage)];

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), sizeof(expectedmessage));
    CU_ASSERT_ARRAY_EQUAL(message, expectedmessage, sizeof(expectedmessage));
}

// RFC8613 6.3.Examples of Compressed COSE Objects Example 2
static void test_oscore_option_example2() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const partialIV[] = {
        0x00
    };
    coap_set_header_oscore(&packet, partialIV, sizeof(partialIV), NULL, 0, OSCORE_EMPTY_ENTRY, 0);

    
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x92,
                                        0x09, 0x00};
    uint8_t message[sizeof(expectedmessage)];

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), sizeof(expectedmessage));
    CU_ASSERT_ARRAY_EQUAL(message, expectedmessage, sizeof(expectedmessage));
}

// RFC8613 6.3.Examples of Compressed COSE Objects Example 3
static void test_oscore_option_example3() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);

    uint8_t const partialIV[] = {
        0x05
    };
    uint8_t const kidContext[] = {
        0x44, 0x61, 0x6c, 0x65, 0x6b
    };
    coap_set_header_oscore(&packet, partialIV, sizeof(partialIV), kidContext, sizeof(kidContext), OSCORE_EMPTY_ENTRY, 0);

    
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x98,
                                        0x19, 0x05, 0x05, 0x44, 0x61, 0x6c, 0x65, 0x6b};
    uint8_t message[sizeof(expectedmessage)];

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), sizeof(expectedmessage));
    CU_ASSERT_ARRAY_EQUAL(message, expectedmessage, sizeof(expectedmessage));
}

// RFC8613 6.3.Examples of Compressed COSE Objects Example 4 
static void test_oscore_option_example4() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    coap_set_header_oscore(&packet, NULL, 0, NULL, 0, NULL, 0);
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x90};

    uint8_t message[sizeof(expectedmessage)];

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), sizeof(expectedmessage));
    CU_ASSERT_ARRAY_EQUAL(message, expectedmessage, sizeof(expectedmessage));
}

// RFC8613 6.3.Examples of Compressed COSE Objects Example 5 
static void test_oscore_option_example5() {
    coap_packet_t packet;
    coap_init_message(&packet, COAP_TYPE_CON, COAP_GET, 0x1234);
    uint8_t const partialIV[] = {
        0x07
    };
    coap_set_header_oscore(&packet, partialIV, 1, NULL, 0, NULL, 0);
    uint8_t const expectedmessage[] =  {0x40, COAP_GET, 0x12, 0x34,
                                        0x92,
                                        0x01, 0x07};

    uint8_t message[sizeof(expectedmessage)];

    CU_ASSERT_EQUAL(coap_serialize_message(&packet, message), sizeof(expectedmessage));
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
    uint8_t const oscoreOption[] = {0x10, 0x05, 0x01, 0x02, 0x03, 0x04};

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
                                0x10, 0x05, 0x01, 0x02,
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
                                0x08, 0x01, 0x02, 0x03,
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
    alg.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    uint8_t kid[] = {0x00};
    uint8_t partialIV[] = {0x25};

    CU_ASSERT_EQUAL(oscore_additional_authenticated_data_get_size(&alg, kid, sizeof(kid), partialIV, sizeof(partialIV)), 21);
}

static void test_oscore_serialize_aad_works() {
    cn_cbor alg;
    memset(&alg, 0, sizeof(cn_cbor));
    alg.type = CN_CBOR_UINT;
    alg.v.uint = COSE_ALGO_AES_CCM_16_64_128;
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

static void test_oscore_context_init_adds_SHA256() {
    oscore_context_t ctx;
    oscore_init(&ctx);
    
    CU_ASSERT_PTR_NOT_NULL(ctx.hkdf);
    CU_ASSERT_EQUAL(ctx.hkdf->id.v.sint, -10);
}

static void test_oscore_context_backend_free_removes_SHA256() {
    oscore_context_t ctx;
    oscore_init(&ctx);

    oscore_backend_free(&ctx);
    
    CU_ASSERT_PTR_NULL(ctx.hkdf);
}

static void test_oscore_derive_context_test_vector1_client() {
    uint8_t const masterSecret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t const masterSalt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40
    };
    
    oscore_context_t ctx;
    oscore_init(&ctx);


    oscore_common_context_t commonCtx;
    memset(&commonCtx, 0, sizeof(oscore_common_context_t));
    commonCtx.hkdfAlgId.type = CN_CBOR_INT;
    commonCtx.hkdfAlgId.v.sint = COSE_ALGO_HKDF_SHA_256;
    commonCtx.aeadAlgId.type = CN_CBOR_UINT;
    commonCtx.aeadAlgId.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    commonCtx.masterSecret = masterSecret;
    commonCtx.masterSecretLen = sizeof(masterSecret);
    commonCtx.masterSalt = masterSalt;
    commonCtx.masterSaltLen = sizeof(masterSalt);
    commonCtx.senderIdLen = 0;
    commonCtx.recipientId[0] = 0x01;
    commonCtx.recipientIdLen = 1;

    uint8_t const expectedSenderKey[16] = {
        0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
        0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff
    };
    uint8_t const expectedRecipientKey[16] = {
        0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
        0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
    };
    uint8_t const expectedCommonIV[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    uint8_t const expectedSenderNonce[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    uint8_t const expectedRecipientNonce[13] = {
        0x47, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x69,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    uint8_t senderNonce[13];
    uint8_t recipientNonce[13];

    oscore_derived_context_t derivedCtx;
    memset(&derivedCtx, 0, sizeof(oscore_derived_context_t));

    CU_ASSERT_EQUAL(oscore_derive_context(&ctx, &commonCtx, &derivedCtx), 0);

    CU_ASSERT_EQUAL(derivedCtx.keyLen, 16);
    CU_ASSERT_EQUAL(derivedCtx.nonceLen, 13);

    CU_ASSERT_ARRAY_EQUAL(derivedCtx.senderKey, expectedSenderKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.recipientKey, expectedRecipientKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.commonIV, expectedCommonIV, 13);

    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.senderId, commonCtx.senderIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, senderNonce), 0);
    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.recipientId, commonCtx.recipientIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, recipientNonce), 0);

    CU_ASSERT_ARRAY_EQUAL(expectedSenderNonce, senderNonce, 13);
    CU_ASSERT_ARRAY_EQUAL(expectedRecipientNonce, recipientNonce, 13);

    oscore_free(&ctx);
}

static void test_oscore_derive_context_test_vector1_server() {
    uint8_t const masterSecret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t const masterSalt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40
    };
    
    oscore_context_t ctx;
    oscore_init(&ctx);


    oscore_common_context_t commonCtx;
    memset(&commonCtx, 0, sizeof(oscore_common_context_t));
    commonCtx.hkdfAlgId.type = CN_CBOR_INT;
    commonCtx.hkdfAlgId.v.sint = COSE_ALGO_HKDF_SHA_256;
    commonCtx.aeadAlgId.type = CN_CBOR_UINT;
    commonCtx.aeadAlgId.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    commonCtx.masterSecret = masterSecret;
    commonCtx.masterSecretLen = sizeof(masterSecret);
    commonCtx.masterSalt = masterSalt;
    commonCtx.masterSaltLen = sizeof(masterSalt);
    commonCtx.recipientIdLen = 0;
    commonCtx.senderId[0] = 0x01;
    commonCtx.senderIdLen = 1;
    
    uint8_t const expectedRecipientKey[16] = {
        0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
        0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff
    };
    uint8_t const expectedSenderKey[16] = {
        0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
        0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
    };
    uint8_t const expectedCommonIV[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };
    
    uint8_t const expectedRecipientNonce[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    uint8_t const expectedSenderNonce[13] = {
        0x47, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x69,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    uint8_t senderNonce[13];
    uint8_t recipientNonce[13];

    oscore_derived_context_t derivedCtx;
    memset(&derivedCtx, 0, sizeof(oscore_derived_context_t));

    CU_ASSERT_EQUAL(oscore_derive_context(&ctx, &commonCtx, &derivedCtx), 0);

    CU_ASSERT_EQUAL(derivedCtx.keyLen, 16);
    CU_ASSERT_EQUAL(derivedCtx.nonceLen, 13);

    CU_ASSERT_ARRAY_EQUAL(derivedCtx.senderKey, expectedSenderKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.recipientKey, expectedRecipientKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.commonIV, expectedCommonIV, 13);

    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.senderId, commonCtx.senderIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, senderNonce), 0);
    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.recipientId, commonCtx.recipientIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, recipientNonce), 0);

    CU_ASSERT_ARRAY_EQUAL(expectedSenderNonce, senderNonce, 13);
    CU_ASSERT_ARRAY_EQUAL(expectedRecipientNonce, recipientNonce, 13);

    oscore_free(&ctx);
}

static void test_oscore_derive_context_test_vector2_client() {
    uint8_t const masterSecret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t* masterSalt = NULL;
    
    oscore_context_t ctx;
    oscore_init(&ctx);


    oscore_common_context_t commonCtx;
    memset(&commonCtx, 0, sizeof(oscore_common_context_t));
    commonCtx.hkdfAlgId.type = CN_CBOR_INT;
    commonCtx.hkdfAlgId.v.sint = COSE_ALGO_HKDF_SHA_256;
    commonCtx.aeadAlgId.type = CN_CBOR_UINT;
    commonCtx.aeadAlgId.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    commonCtx.masterSecret = masterSecret;
    commonCtx.masterSecretLen = sizeof(masterSecret);
    commonCtx.masterSalt = masterSalt;
    commonCtx.masterSaltLen = 0;
    commonCtx.senderId[0] = 0x00;
    commonCtx.senderIdLen = 1;
    commonCtx.recipientId[0] = 0x01;
    commonCtx.recipientIdLen = 1;

    uint8_t const expectedSenderKey[16] = {
        0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
        0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41
    };
    uint8_t const expectedRecipientKey[16] = {
        0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd,
        0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d, 0x7d, 0xda
    };
    uint8_t const expectedCommonIV[13] = {
        0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
        0x10, 0xc5, 0x2e, 0x99, 0xf9
    };

    uint8_t const expectedRecipientNonce[13] = {
        0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe8,
        0x10, 0xc5, 0x2e, 0x99, 0xf9
    };

    uint8_t const expectedSenderNonce[13] = {
        0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
        0x10, 0xc5, 0x2e, 0x99, 0xf9
    };

    uint8_t senderNonce[13];
    uint8_t recipientNonce[13];

    oscore_derived_context_t derivedCtx;
    memset(&derivedCtx, 0, sizeof(oscore_derived_context_t));

    CU_ASSERT_EQUAL(oscore_derive_context(&ctx, &commonCtx, &derivedCtx), 0);

    CU_ASSERT_EQUAL(derivedCtx.keyLen, 16);
    CU_ASSERT_EQUAL(derivedCtx.nonceLen, 13);

    CU_ASSERT_ARRAY_EQUAL(derivedCtx.senderKey, expectedSenderKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.recipientKey, expectedRecipientKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.commonIV, expectedCommonIV, 13);

    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.senderId, commonCtx.senderIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, senderNonce), 0);
    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.recipientId, commonCtx.recipientIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, recipientNonce), 0);

    CU_ASSERT_ARRAY_EQUAL(expectedSenderNonce, senderNonce, 13);
    CU_ASSERT_ARRAY_EQUAL(expectedRecipientNonce, recipientNonce, 13);

    oscore_free(&ctx);
}

static void test_oscore_derive_context_test_vector2_server() {
    uint8_t const masterSecret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t* masterSalt = NULL;
    
    oscore_context_t ctx;
    oscore_init(&ctx);


    oscore_common_context_t commonCtx;
    memset(&commonCtx, 0, sizeof(oscore_common_context_t));
    commonCtx.hkdfAlgId.type = CN_CBOR_INT;
    commonCtx.hkdfAlgId.v.sint = COSE_ALGO_HKDF_SHA_256;
    commonCtx.aeadAlgId.type = CN_CBOR_UINT;
    commonCtx.aeadAlgId.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    commonCtx.masterSecret = masterSecret;
    commonCtx.masterSecretLen = sizeof(masterSecret);
    commonCtx.masterSalt = masterSalt;
    commonCtx.masterSaltLen = 0;
    commonCtx.senderId[0] = 0x01;
    commonCtx.senderIdLen = 1;
    commonCtx.recipientId[0] = 0x00;
    commonCtx.recipientIdLen = 1;

    uint8_t const expectedRecipientKey[16] = {
        0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
        0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41
    };
    uint8_t const expectedSenderKey[16] = {
        0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd,
        0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d, 0x7d, 0xda
    };
    uint8_t const expectedCommonIV[13] = {
        0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
        0x10, 0xc5, 0x2e, 0x99, 0xf9
    };

    uint8_t const expectedSenderNonce[13] = {
        0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe8,
        0x10, 0xc5, 0x2e, 0x99, 0xf9
    };
    
    uint8_t const expectedRecipientNonce[13] = {
        0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
        0x10, 0xc5, 0x2e, 0x99, 0xf9
    };

    uint8_t senderNonce[13];
    uint8_t recipientNonce[13];

    oscore_derived_context_t derivedCtx;
    memset(&derivedCtx, 0, sizeof(oscore_derived_context_t));

    CU_ASSERT_EQUAL(oscore_derive_context(&ctx, &commonCtx, &derivedCtx), 0);

    CU_ASSERT_EQUAL(derivedCtx.keyLen, 16);
    CU_ASSERT_EQUAL(derivedCtx.nonceLen, 13);

    CU_ASSERT_ARRAY_EQUAL(derivedCtx.senderKey, expectedSenderKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.recipientKey, expectedRecipientKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.commonIV, expectedCommonIV, 13);

    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.senderId, commonCtx.senderIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, senderNonce), 0);
    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.recipientId, commonCtx.recipientIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, recipientNonce), 0);

    CU_ASSERT_ARRAY_EQUAL(expectedSenderNonce, senderNonce, 13);
    CU_ASSERT_ARRAY_EQUAL(expectedRecipientNonce, recipientNonce, 13);

    oscore_free(&ctx);
}

static void test_oscore_derive_context_test_vector3_client() {
    uint8_t const masterSecret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t const masterSalt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40
    };

    uint8_t const idContext[] = {
        0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3
    };
    
    oscore_context_t ctx;
    oscore_init(&ctx);


    oscore_common_context_t commonCtx;
    memset(&commonCtx, 0, sizeof(oscore_common_context_t));
    commonCtx.hkdfAlgId.type = CN_CBOR_INT;
    commonCtx.hkdfAlgId.v.sint = COSE_ALGO_HKDF_SHA_256;
    commonCtx.aeadAlgId.type = CN_CBOR_UINT;
    commonCtx.aeadAlgId.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    commonCtx.masterSecret = masterSecret;
    commonCtx.masterSecretLen = sizeof(masterSecret);
    commonCtx.masterSalt = masterSalt;
    commonCtx.masterSaltLen = sizeof(masterSalt);
    commonCtx.idContext = idContext;
    commonCtx.idContextLen = sizeof(idContext);
    commonCtx.senderIdLen = 0;
    commonCtx.recipientId[0] = 0x01;
    commonCtx.recipientIdLen = 1;

    uint8_t const expectedSenderKey[16] = {
        0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88,
        0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92
    };
    uint8_t const expectedRecipientKey[16] = {
        0xe3, 0x9a, 0x0c, 0x7c, 0x77, 0xb4, 0x3f, 0x03,
        0xb4, 0xb3, 0x9a, 0xb9, 0xa2, 0x68, 0x69, 0x9f
    };
    uint8_t const expectedCommonIV[13] = {
        0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
        0x0b, 0x71, 0x81, 0xb8, 0x5e
    };

    uint8_t const expectedSenderNonce[13] = {
        0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
        0x0b, 0x71, 0x81, 0xb8, 0x5e
    };
    
    uint8_t const expectedRecipientNonce[13] = {
        0x2d, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1d,
        0x0b, 0x71, 0x81, 0xb8, 0x5e
    };

    uint8_t senderNonce[13];
    uint8_t recipientNonce[13];

    oscore_derived_context_t derivedCtx;
    memset(&derivedCtx, 0, sizeof(oscore_derived_context_t));

    CU_ASSERT_EQUAL(oscore_derive_context(&ctx, &commonCtx, &derivedCtx), 0);

    CU_ASSERT_EQUAL(derivedCtx.keyLen, 16);
    CU_ASSERT_EQUAL(derivedCtx.nonceLen, 13);

    CU_ASSERT_ARRAY_EQUAL(derivedCtx.senderKey, expectedSenderKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.recipientKey, expectedRecipientKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.commonIV, expectedCommonIV, 13);

    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.senderId, commonCtx.senderIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, senderNonce), 0);
    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.recipientId, commonCtx.recipientIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, recipientNonce), 0);

    CU_ASSERT_ARRAY_EQUAL(expectedSenderNonce, senderNonce, 13);
    CU_ASSERT_ARRAY_EQUAL(expectedRecipientNonce, recipientNonce, 13);

    oscore_free(&ctx);
}

static void test_oscore_derive_context_test_vector3_server() {
    uint8_t const masterSecret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    uint8_t const masterSalt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40
    };

    uint8_t const idContext[] = {
        0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3
    };
    
    oscore_context_t ctx;
    oscore_init(&ctx);


    oscore_common_context_t commonCtx;
    memset(&commonCtx, 0, sizeof(oscore_common_context_t));
    commonCtx.hkdfAlgId.type = CN_CBOR_INT;
    commonCtx.hkdfAlgId.v.sint = COSE_ALGO_HKDF_SHA_256;
    commonCtx.aeadAlgId.type = CN_CBOR_UINT;
    commonCtx.aeadAlgId.v.uint = COSE_ALGO_AES_CCM_16_64_128;
    commonCtx.masterSecret = masterSecret;
    commonCtx.masterSecretLen = sizeof(masterSecret);
    commonCtx.masterSalt = masterSalt;
    commonCtx.masterSaltLen = sizeof(masterSalt);
    commonCtx.idContext = idContext;
    commonCtx.idContextLen = sizeof(idContext);
    commonCtx.senderId[0] = 0x01;
    commonCtx.senderIdLen = 1;
    commonCtx.recipientIdLen = 0;

    uint8_t const expectedRecipientKey[16] = {
        0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88,
        0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92
    };
    uint8_t const expectedSenderKey[16] = {
        0xe3, 0x9a, 0x0c, 0x7c, 0x77, 0xb4, 0x3f, 0x03,
        0xb4, 0xb3, 0x9a, 0xb9, 0xa2, 0x68, 0x69, 0x9f
    };
    uint8_t const expectedCommonIV[13] = {
        0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
        0x0b, 0x71, 0x81, 0xb8, 0x5e
    };
    
    uint8_t const expectedRecipientNonce[13] = {
        0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
        0x0b, 0x71, 0x81, 0xb8, 0x5e
    };
    
    uint8_t const expectedSenderNonce[13] = {
        0x2d, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1d,
        0x0b, 0x71, 0x81, 0xb8, 0x5e
    };

    uint8_t senderNonce[13];
    uint8_t recipientNonce[13];

    oscore_derived_context_t derivedCtx;
    memset(&derivedCtx, 0, sizeof(oscore_derived_context_t));

    CU_ASSERT_EQUAL(oscore_derive_context(&ctx, &commonCtx, &derivedCtx), 0);

    CU_ASSERT_EQUAL(derivedCtx.keyLen, 16);
    CU_ASSERT_EQUAL(derivedCtx.nonceLen, 13);

    CU_ASSERT_ARRAY_EQUAL(derivedCtx.senderKey, expectedSenderKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.recipientKey, expectedRecipientKey, 16);
    CU_ASSERT_ARRAY_EQUAL(derivedCtx.commonIV, expectedCommonIV, 13);

    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.senderId, commonCtx.senderIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, senderNonce), 0);
    CU_ASSERT_EQUAL(oscore_derive_nonce(commonCtx.recipientId, commonCtx.recipientIdLen, derivedCtx.commonIV, derivedCtx.nonceLen, NULL, 0, recipientNonce), 0);

    CU_ASSERT_ARRAY_EQUAL(expectedSenderNonce, senderNonce, 13);
    CU_ASSERT_ARRAY_EQUAL(expectedRecipientNonce, recipientNonce, 13);

    oscore_free(&ctx);
}

static void test_oscore_message_test_vector4_request_client() {
    uint8_t serializedCoAP[] = {
        0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
        0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
        0x73, 0x74, 0x83, 0x74, 0x76, 0x31
    };

    uint8_t const senderKey[16] = {
        0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
        0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff
    };

    uint8_t const commonIV[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    cn_cbor aeadAlg;
    memset(&aeadAlg, 0, sizeof(cn_cbor));
    aeadAlg.type = CN_CBOR_UINT;
    aeadAlg.v.uint = COSE_ALGO_AES_CCM_16_64_128;

    size_t const senderSequenceNumber = 20;

    oscore_context_t ctx;
    oscore_init(&ctx);

    oscore_sender_context_t sender;
    memset(&sender, 0, sizeof(oscore_sender_context_t));
    sender.senderIdLen = 0;
    sender.senderKey = senderKey;
    sender.senderKeyLen = sizeof(senderKey);
    sender.aeadAlgId = &aeadAlg;
    sender.commonIV = commonIV;
    sender.nonceLen = sizeof(commonIV);
    sender.senderSequenceNumber = senderSequenceNumber;
    

    coap_packet_t coap_msg;
    memset(&coap_msg, 0, sizeof(coap_packet_t));

    coap_parse_message(&coap_msg, serializedCoAP, sizeof(serializedCoAP));

    oscore_message_t oscore_msg;
    memset(&oscore_msg, 0, sizeof(oscore_message_t));
    oscore_msg.packet = &coap_msg;

    uint8_t serializedOscore[35];
    uint8_t const expectedOscore[35] = {
        0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x39,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
        0x62, 0x09, 0x14, 0xff, 0x61, 0x2f, 0x10, 0x92, 0xf1,
        0x77, 0x6f, 0x1c, 0x16, 0x68, 0xb3, 0x82, 0x5e
    };

    CU_ASSERT_EQUAL(oscore_message_encrypt(&ctx, &sender, &oscore_msg), 0);

    CU_ASSERT_EQUAL(coap_serialize_message(&coap_msg, serializedOscore), 35);

    CU_ASSERT_ARRAY_EQUAL(serializedOscore, expectedOscore, 35);
    OSCORE_FREE(coap_msg.payload);
    oscore_free(&ctx);
}

static void test_oscore_message_test_vector5_request_client() {
    uint8_t serializedCoAP[] = {
        0x44, 0x01, 0x71, 0xc3, 0x00, 0x00, 0xb9, 0x32,
        0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
        0x73, 0x74, 0x83, 0x74, 0x76, 0x31
    };

    uint8_t const senderKey[16] = {
        0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
        0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41
    };

    uint8_t const commonIV[13] = {
        0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9,
        0x10, 0xc5, 0x2e, 0x99, 0xf9
    };

    uint8_t const senderId[1] = {
        0x00
    };

    cn_cbor aeadAlg;
    memset(&aeadAlg, 0, sizeof(cn_cbor));
    aeadAlg.type = CN_CBOR_UINT;
    aeadAlg.v.uint = COSE_ALGO_AES_CCM_16_64_128;

    size_t const senderSequenceNumber = 20;

    oscore_context_t ctx;
    oscore_init(&ctx);

    oscore_sender_context_t sender;
    memset(&sender, 0, sizeof(oscore_sender_context_t));
    sender.senderId = senderId;
    sender.senderIdLen = sizeof(senderId);
    sender.senderKey = senderKey;
    sender.senderKeyLen = sizeof(senderKey);
    sender.aeadAlgId = &aeadAlg;
    sender.commonIV = commonIV;
    sender.nonceLen = sizeof(commonIV);
    sender.senderSequenceNumber = senderSequenceNumber;
    

    coap_packet_t coap_msg;
    memset(&coap_msg, 0, sizeof(coap_packet_t));

    coap_parse_message(&coap_msg, serializedCoAP, sizeof(serializedCoAP));

    oscore_message_t oscore_msg;
    memset(&oscore_msg, 0, sizeof(oscore_message_t));
    oscore_msg.packet = &coap_msg;

    uint8_t serializedOscore[36];
    uint8_t const expectedOscore[36] = {
        0x44, 0x02, 0x71, 0xc3, 0x00, 0x00, 0xb9, 0x32,
        0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
        0x73, 0x74, 0x63, 0x09, 0x14, 0x00, 0xff, 0x4e,
        0xd3, 0x39, 0xa5, 0xa3, 0x79, 0xb0, 0xb8, 0xbc,
        0x73, 0x1f, 0xff, 0xb0
    };

    CU_ASSERT_EQUAL(oscore_message_encrypt(&ctx, &sender, &oscore_msg), 0);

    CU_ASSERT_EQUAL(coap_serialize_message(&coap_msg, serializedOscore), 36);

    CU_ASSERT_ARRAY_EQUAL(serializedOscore, expectedOscore, 36);
    OSCORE_FREE(coap_msg.payload);
    oscore_free(&ctx);
}

static void test_oscore_message_test_vector6_request_client() {
    uint8_t serializedCoAP[] = {
         0x44, 0x01, 0x2f, 0x8e, 0xef, 0x9b, 0xbf, 0x7a,
         0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
         0x73, 0x74, 0x83, 0x74, 0x76, 0x31
    };

    uint8_t const senderKey[16] = {
        0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88,
        0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92
    };

    uint8_t const idContext[8] = {
        0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3
    };

    uint8_t const commonIV[13] = {
        0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c,
        0x0b, 0x71, 0x81, 0xb8, 0x5e
    };

    cn_cbor aeadAlg;
    memset(&aeadAlg, 0, sizeof(cn_cbor));
    aeadAlg.type = CN_CBOR_UINT;
    aeadAlg.v.uint = COSE_ALGO_AES_CCM_16_64_128;

    size_t const senderSequenceNumber = 20;

    oscore_context_t ctx;
    oscore_init(&ctx);

    oscore_sender_context_t sender;
    memset(&sender, 0, sizeof(oscore_sender_context_t));
    sender.senderIdLen = 0;
    sender.idContext = idContext;
    sender.idContextLen = sizeof(idContext);
    sender.senderKey = senderKey;
    sender.senderKeyLen = sizeof(senderKey);
    sender.aeadAlgId = &aeadAlg;
    sender.commonIV = commonIV;
    sender.nonceLen = sizeof(commonIV);
    sender.senderSequenceNumber = senderSequenceNumber;
    

    coap_packet_t coap_msg;
    memset(&coap_msg, 0, sizeof(coap_packet_t));

    coap_parse_message(&coap_msg, serializedCoAP, sizeof(serializedCoAP));

    oscore_message_t oscore_msg;
    memset(&oscore_msg, 0, sizeof(oscore_message_t));
    oscore_msg.packet = &coap_msg;

    uint8_t serializedOscore[44];
    uint8_t const expectedOscore[44] = {
        0x44, 0x02, 0x2f, 0x8e, 0xef, 0x9b, 0xbf, 0x7a,
        0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
        0x73, 0x74, 0x6b, 0x19, 0x14, 0x08, 0x37, 0xcb,
        0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3, 0xff, 0x72,
        0xcd, 0x72, 0x73, 0xfd, 0x33, 0x1a, 0xc4, 0x5c,
        0xff, 0xbe, 0x55, 0xc3
    };

    CU_ASSERT_EQUAL(oscore_message_encrypt(&ctx, &sender, &oscore_msg), 0);

    CU_ASSERT_EQUAL(coap_serialize_message(&coap_msg, serializedOscore), 44);

    CU_ASSERT_ARRAY_EQUAL(serializedOscore, expectedOscore, 44);
    OSCORE_FREE(coap_msg.payload);
    oscore_free(&ctx);
}

static void test_oscore_message_test_vector7_response_server() {
    uint8_t serializedCoAP[] = {
         0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
         0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
         0x6f, 0x72, 0x6c, 0x64, 0x21
    };

    uint8_t const senderKey[16] = {
        0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
        0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
    };

    uint8_t const commonIV[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    uint8_t const senderId[1] = {
        0x01
    };

    cn_cbor aeadAlg;
    memset(&aeadAlg, 0, sizeof(cn_cbor));
    aeadAlg.type = CN_CBOR_UINT;
    aeadAlg.v.uint = COSE_ALGO_AES_CCM_16_64_128;

    size_t const senderSequenceNumber = 0;

    oscore_context_t ctx;
    oscore_init(&ctx);

    oscore_sender_context_t sender;
    memset(&sender, 0, sizeof(oscore_sender_context_t));
    sender.senderId = senderId;
    sender.senderIdLen = sizeof(senderId);
    sender.senderKey = senderKey;
    sender.senderKeyLen = sizeof(senderKey);
    sender.aeadAlgId = &aeadAlg;
    sender.commonIV = commonIV;
    sender.nonceLen = sizeof(commonIV);
    sender.senderSequenceNumber = senderSequenceNumber;
    

    coap_packet_t coap_msg;
    memset(&coap_msg, 0, sizeof(coap_packet_t));
    

    coap_parse_message(&coap_msg, serializedCoAP, sizeof(serializedCoAP));

    oscore_message_t oscore_msg;
    memset(&oscore_msg, 0, sizeof(oscore_message_t));
    oscore_msg.packet = &coap_msg;
    // populated from request
    oscore_msg.partialIV[0] = 0x14;
    oscore_msg.partialIVLen = 1;
    oscore_msg.id = NULL; // sender id was empty byte array
    oscore_msg.idLen = 0;

    uint8_t serializedOscore[32];
    uint8_t const expectedOscore[32] = {
        0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
        0x90, 0xff, 0xdb, 0xaa, 0xd1, 0xe9, 0xa7, 0xe7,
        0xb2, 0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37,
        0x83, 0x03, 0xcd, 0xaf, 0xae, 0x11, 0x91, 0x06
    };

    CU_ASSERT_EQUAL(oscore_message_encrypt(&ctx, &sender, &oscore_msg), 0);

    CU_ASSERT_EQUAL(coap_serialize_message(&coap_msg, serializedOscore), 32);


    CU_ASSERT_ARRAY_EQUAL(serializedOscore, expectedOscore, 32);
    OSCORE_FREE(coap_msg.payload);
    oscore_free(&ctx);
}

static void test_oscore_message_test_vector8_response_server() {
    uint8_t serializedCoAP[] = {
         0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
         0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57,
         0x6f, 0x72, 0x6c, 0x64, 0x21
    };

    uint8_t const senderKey[16] = {
        0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
        0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10
    };

    uint8_t const commonIV[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    uint8_t const senderId[1] = {
        0x01
    };

    cn_cbor aeadAlg;
    memset(&aeadAlg, 0, sizeof(cn_cbor));
    aeadAlg.type = CN_CBOR_UINT;
    aeadAlg.v.uint = COSE_ALGO_AES_CCM_16_64_128;

    size_t const senderSequenceNumber = 0;

    oscore_context_t ctx;
    oscore_init(&ctx);

    oscore_sender_context_t sender;
    memset(&sender, 0, sizeof(oscore_sender_context_t));
    sender.senderId = senderId;
    sender.senderIdLen = sizeof(senderId);
    sender.senderKey = senderKey;
    sender.senderKeyLen = sizeof(senderKey);
    sender.aeadAlgId = &aeadAlg;
    sender.commonIV = commonIV;
    sender.nonceLen = sizeof(commonIV);
    sender.senderSequenceNumber = senderSequenceNumber;
    

    coap_packet_t coap_msg;
    memset(&coap_msg, 0, sizeof(coap_packet_t));
    

    coap_parse_message(&coap_msg, serializedCoAP, sizeof(serializedCoAP));

    oscore_message_t oscore_msg;
    memset(&oscore_msg, 0, sizeof(oscore_message_t));
    oscore_msg.packet = &coap_msg;
    oscore_msg.partialIV[0] = 0x14;
    oscore_msg.partialIVLen = 1;
    // generate new partialIV
    oscore_msg.generatePartialIV = true;

    uint8_t serializedOscore[34];
    uint8_t const expectedOscore[34] = {
        0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
        0x92, 0x01, 0x00, 0xff, 0x4d, 0x4c, 0x13, 0x66,
        0x93, 0x84, 0xb6, 0x73, 0x54, 0xb2, 0xb6, 0x17,
        0x5f, 0xf4, 0xb8, 0x65, 0x8c, 0x66, 0x6a, 0x6c,
        0xf8, 0x8e
    };

    CU_ASSERT_EQUAL(oscore_message_encrypt(&ctx, &sender, &oscore_msg), 0);
    CU_ASSERT_EQUAL(coap_serialize_message(&coap_msg, serializedOscore), 34);

    CU_ASSERT_ARRAY_EQUAL(serializedOscore, expectedOscore, 34);
    OSCORE_FREE(coap_msg.payload);
    oscore_free(&ctx);
}


static void temp_test() {

    oscore_context_t ctx;
    oscore_init(&ctx);
    

    coap_packet_t coap_msg;
    memset(&coap_msg, 0, sizeof(coap_packet_t));
    oscore_message_t oscore_msg;
    memset(&oscore_msg, 0, sizeof(oscore_message_t));
    oscore_msg.packet = &coap_msg;

    uint8_t const recipientKey[16] = {
        0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
        0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff
    };

    uint8_t const commonIV[13] = {
        0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68,
        0xee, 0xfb, 0x54, 0x98, 0x7c
    };

    cn_cbor aeadAlg;
    memset(&aeadAlg, 0, sizeof(cn_cbor));
    aeadAlg.type = CN_CBOR_UINT;
    aeadAlg.v.uint = COSE_ALGO_AES_CCM_16_64_128;

    oscore_recipient_context_t recipient;
    memset(&recipient, 0, sizeof(oscore_recipient_context_t));
    recipient.recipientKey = recipientKey;
    recipient.recipientKeyLen = sizeof(recipientKey);
    recipient.commonIV = commonIV;
    recipient.nonceLen = sizeof(commonIV);
    recipient.aeadAlgId = &aeadAlg;
    recipient.highestValidatedSequenceNumber = 0;
    ctx.recipient = &recipient;


    uint8_t oscoremsg[35] = {
        0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x39,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
        0x62, 0x09, 0x14, 0xff, 0x61, 0x2f, 0x10, 0x92, 0xf1,
        0x77, 0x6f, 0x1c, 0x16, 0x68, 0xb3, 0x82, 0x5e
    };

    oscore_message_decrypt(&ctx, &oscore_msg, oscoremsg, sizeof(oscoremsg));

    oscore_free(&ctx);
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
         // RFC Option Value examples
        { "[OPTION] header compression example 1", test_oscore_option_example1 },
        { "[OPTION] header compression example 2", test_oscore_option_example2 },
        { "[OPTION] header compression example 3", test_oscore_option_example3 },
        { "[OPTION] header compression example 4", test_oscore_option_example4 },
        { "[OPTION] header compression example 5", test_oscore_option_example5 },

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

        // context tests
        { "[CTX] backend inits HMAC SHA256 alg", test_oscore_context_init_adds_SHA256 },
        { "[CTX] backend frees HMAC SHA256 alg", test_oscore_context_backend_free_removes_SHA256 },

        // derive ctx
        { "[dCTX] test vector 1 client", test_oscore_derive_context_test_vector1_client }, 
        { "[dCTX] test vector 1 server", test_oscore_derive_context_test_vector1_server },
        { "[dCTX] test vector 2 client", test_oscore_derive_context_test_vector2_client},
        { "[dCTX] test vector 2 server", test_oscore_derive_context_test_vector2_server },
        { "[dCTX] test vector 3 client", test_oscore_derive_context_test_vector3_client},
        { "[dCTX] test vector 3 server", test_oscore_derive_context_test_vector3_server },

        // Messages
        { "[MSG] test vector 4 OSCORE Request, Client", test_oscore_message_test_vector4_request_client },
        { "[MSG] test vector 5 OSCORE Request, Client", test_oscore_message_test_vector5_request_client },
        { "[MSG] test vector 6 OSCORE Request, Client", test_oscore_message_test_vector6_request_client },
        { "[MSG] test vector 7 OSCORE Response, Server", test_oscore_message_test_vector7_response_server },
        { "[MSG] test vector 8 OSCORE Response, Server", test_oscore_message_test_vector8_response_server },

        { "", temp_test },
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