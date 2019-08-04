
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
    unsigned char buf_enc_out[1024 + 1] = { 0 };
    unsigned char buf_dec_out[1024 + 1] = { 0 };
    unsigned char buf_to_enc[] = "这是一段base64后带加号和斜线的句子";
    unsigned char buf_to_dec[] = "6L+Z5piv5LiA5q61YmFzZTY05ZCO5bim5Yqg5Y+35ZKM5pac57q/55qE5Y+l5a2Q";

    /* test encode */
    ret = mbedtls_base64_encode(buf_enc_out, buf_len, &out_len, buf_to_enc, sizeof(buf_to_enc) - 1);
    if (ret != 0) {
        printf("! mbedtls_md_setup() returned -0x%04x\n", -ret);
        goto exit;
    }
    printf("test encode:\ninput  buffer: %s\noutput buffer: %s\n", buf_to_enc, buf_enc_out);
    if (out_len != strlen((char *)buf_to_dec)) {
        ret = -1;
        goto exit;
    }
    ret = memcmp(buf_enc_out, buf_to_dec, sizeof(buf_to_dec));
    if (ret != 0) {
        printf("encode test faild.");
        goto exit;
    }

    /* test decode */
    ret = mbedtls_base64_decode(buf_dec_out, buf_len, &out_len, buf_to_dec, sizeof(buf_to_dec) - 1);
    if (ret != 0) {
        printf("! mbedtls_md_setup() returned -0x%04x\n", -ret);
        goto exit;
    }
    printf("test decode:\ninput  buffer: %s\noutput buffer: %s\n", buf_to_dec, buf_dec_out);
    if (out_len != strlen((char *)buf_to_enc)) {
        ret = -1;
        goto exit;
    }
    ret = memcmp(buf_dec_out, buf_to_enc, sizeof(buf_to_enc));
    if (ret != 0) {
        printf("decode test faild.");
        goto exit;
    }

exit:
    return ret;
}
