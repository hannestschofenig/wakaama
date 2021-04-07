#ifndef OSCORE_CONFIG_H_
#define OSCORE_CONFIG_H_

// maximum length of a key
#define OSCORE_MAXKEYLEN 16
// maximum length of a nonce
#define OSCORE_MAXNONCELEN 13
// maximum Id length as specified in RFC8613 3.3
#define OSCORE_MAX_ID_LEN (OSCORE_MAXNONCELEN - 6)
// maximum length of HKDF
#define OSCORE_HKDF_MAXLEN 32


#define OSCORE_MALLOC(size) lwm2m_malloc(size)
#define OSCORE_FREE(ptr) lwm2m_free(ptr)




#endif