//#include <stdio.h>
//#include <string.h>
//#include <stdint.h>
//#include "hmac_sha1.h"

/*
 * Verification result generate from
 * https://www.liavaag.org/English/SHA-Generator/HMAC/
 * http://tool.oschina.net/encrypt?type=2
 *
 * */

#define ASSERT_SUCCESS (0)
#define ASSERT_FAIL    (1)

//int main(int argc, const char * argv[]) {
//    int i;
//    size_t out_len = 0;
//    char sec_key[] = "deps";
//    char data[] = "aggresss";
//    char out[SHA1_DIGEST_SIZE] = {0};
//    char out_hexstr[SHA1_DIGEST_SIZE * 2 + 1] = {0};
//    char expect_hmacsha1_result[] = "b8cf05a896659c144efd03b6d3c00b42eb32faae";
//
//    /* hmac_sha1 workflow */
//    out_len = hmac_sha1((uint8_t*)sec_key, strlen(sec_key), (uint8_t*)data,
//            strlen(data), (uint8_t*)out, sizeof(out));
//    if (out_len != SHA1_DIGEST_SIZE)
//        return ASSERT_FAIL;
//    for(i = 0; i< SHA1_DIGEST_SIZE; i++) {
//        sprintf((char *)(out_hexstr + i * 2), "%02x", *(unsigned char *)(out + i));
//    }
//    printf("data: %s\nkey: %s\nHMAC-SHA1: %s\n", data, sec_key, out_hexstr);
//
//    return strncmp(expect_hmacsha1_result, out_hexstr, SHA1_DIGEST_SIZE * 2);
//}




#include <string.h>
#include <stdio.h>
#include "mbedtls/md.h"

#define mbedtls_printf     printf

int main(void)
{
    int ret;
    unsigned char secret[] = "a secret";
    unsigned char buffer[] = "some data to hash";
    unsigned char digest[32];
    mbedtls_md_context_t sha_ctx;

    mbedtls_md_init(&sha_ctx);
    memset(digest, 0x00, sizeof(digest));

    ret = mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0)
    {
        mbedtls_printf("  ! mbedtls_md_setup() returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_md_hmac_starts(&sha_ctx, secret, sizeof(secret) - 1);
    mbedtls_md_hmac_update(&sha_ctx, buffer, sizeof(buffer) - 1);
    mbedtls_md_hmac_finish(&sha_ctx, digest );

    mbedtls_printf("HMAC: ");
    for (int i = 0; i < sizeof(digest); i++)
        mbedtls_printf("%02X", digest[i]);
    mbedtls_printf("\n");

exit:
    mbedtls_md_free( &sha_ctx );

    return ret;
}
