
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/base64.h"

#define ASSERT_SUCCESS (0)
#define ASSERT_FAIL    (1)

/*
 * Verification result generate from
 * http://tool.oschina.net/encrypt?type=3
 *
 * */

int main(void)
{
    int ret;
    size_t buf_len = 1024;
    size_t out_len;
    unsigned char buf_out[1024 + 1] = {0};
    unsigned char buf_in[] = "这是一段base64后带加号和斜线的句子";
    unsigned char expect_b64_string[] = "6L+Z5piv5LiA5q61YmFzZTY05ZCO5bim5Yqg5Y+35ZKM5pac57q/55qE5Y+l5a2Q";

    ret = mbedtls_base64_encode(buf_out, buf_len, &out_len, buf_in, sizeof(buf_in) - 1);
    if (ret != 0) {
        printf("! mbedtls_md_setup() returned -0x%04x\n", -ret);
        goto exit;
    }
    printf("in  buffer: %s\n", buf_in);
    printf("out length: %zu\n", out_len);
    printf("out buffer: %s\n", buf_out);

    if (out_len != strlen((char *)expect_b64_string)) {
        ret = -1;
        goto exit;
    }
    ret = memcmp(buf_out, expect_b64_string, sizeof(expect_b64_string));

exit:
    return ret;
}
