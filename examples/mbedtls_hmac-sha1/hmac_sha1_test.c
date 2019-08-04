#include <string.h>
#include <stdio.h>
#include "mbedtls/md.h"

/*
 * Verification result generate from
 * https://www.liavaag.org/English/SHA-Generator/HMAC/
 * http://tool.oschina.net/encrypt?type=2
 *
 * */

#define ASSERT_SUCCESS (0)
#define ASSERT_FAIL    (1)
#define SHA1_DIGEST_SIZE 20

int main(void)
{
    int ret, i;
    unsigned char secret[] = "deps";
    unsigned char buffer[] = "aggresss";
    unsigned char digest[SHA1_DIGEST_SIZE];
    char out_hexstr[SHA1_DIGEST_SIZE * 2 + 1] = { 0 };
    char expect_hmacsha1_result[] = "b8cf05a896659c144efd03b6d3c00b42eb32faae";
    mbedtls_md_context_t sha_ctx;

    mbedtls_md_init(&sha_ctx);
    memset(digest, 0x00, sizeof(digest));

    ret = mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    if (ret != 0) {
        printf("! mbedtls_md_setup() returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_md_hmac_starts(&sha_ctx, secret, sizeof(secret) - 1);
    mbedtls_md_hmac_update(&sha_ctx, buffer, sizeof(buffer) - 1);
    mbedtls_md_hmac_finish(&sha_ctx, digest);

    for (i = 0; i < SHA1_DIGEST_SIZE; i++) {
        sprintf((char *) (out_hexstr + i * 2), "%02x", *(unsigned char *) (digest + i));
    }
    printf("buffer: %s\nkey: %s\nHMAC-SHA1: %s\n", buffer, secret, out_hexstr);
    ret = strncmp(expect_hmacsha1_result, out_hexstr, SHA1_DIGEST_SIZE * 2);

exit:
    mbedtls_md_free(&sha_ctx);
    return ret;
}
