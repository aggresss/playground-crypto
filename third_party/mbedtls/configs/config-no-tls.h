/**
 * \file config-no-tls.h
 *
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME


/* mbed TLS modules */
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_BASE64_C

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */

