#include <stdio.h>
#include <string.h>
#include "mbedtls/md5.h"

/*
 * Verification result generate from
 * http://tool.oschina.net/encrypt?type=2
 *
 * */

#define ASSERT_SUCCESS (0)
#define ASSERT_FAIL    (1)
#define MD5_DIGEST_SIZE 16

int main(int argc, const char * argv[])
{
    int i, ret;
    unsigned char buffer[] = "aggresss";
    unsigned char out[MD5_DIGEST_SIZE] = { 0 };
    char out_hexstr[MD5_DIGEST_SIZE * 2 + 1] = { 0 };
    char expect_md5_result[] = "b665a16ea74e08a4003f0257f215c754";
    mbedtls_md5_context md5_ctx;

    /* md5 workflow */
    mbedtls_md5_init(&md5_ctx);
    mbedtls_md5_starts(&md5_ctx);
    mbedtls_md5_update(&md5_ctx, buffer, sizeof(buffer) - 1);
    mbedtls_md5_finish(&md5_ctx, out);

    for (i = 0; i < MD5_DIGEST_SIZE; i++) {
        sprintf((char *) (out_hexstr + i * 2), "%02x", *(unsigned char *) (out + i));
    }
    printf("buffer: %s\nMD5: %s\n", buffer, out_hexstr);

    ret = strncmp(expect_md5_result, out_hexstr, MD5_DIGEST_SIZE * 2);

    mbedtls_md5_free(&md5_ctx);
    return ret;
}

