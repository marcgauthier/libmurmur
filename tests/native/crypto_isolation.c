#include <stddef.h>
#include <string.h>

/* A host's independent mbedTLS implementation must coexist with Murmur's. */
int mbedtls_sha256(const unsigned char *input, size_t length,
                   unsigned char *output, int is224) {
    (void)input; (void)length; (void)output; (void)is224;
    return -123;
}
extern int murmur_mbedtls_sha256(const unsigned char *, size_t,
                                 unsigned char *, int);
int main(void) {
    static const unsigned char expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    unsigned char digest[32];
    if (mbedtls_sha256(NULL, 0, digest, 0) != -123) return 1;
    if (murmur_mbedtls_sha256((const unsigned char *)"abc", 3, digest, 0)) return 2;
    return memcmp(digest, expected, sizeof(digest)) != 0;
}
