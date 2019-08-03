# ------------------------------------------------------------------------------
# CMakeLists.txt for playground-crypto/third_party/mbedtls/library
# ------------------------------------------------------------------------------

include_directories(${CMAKE_CURRENT_LIST_DIR}/../configs)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include)

set(src_crypto
    aes.c
    aesni.c
    arc4.c
    aria.c
    asn1parse.c
    asn1write.c
    base64.c
    bignum.c
    blowfish.c
    camellia.c
    ccm.c
    chacha20.c
    chachapoly.c
    cipher.c
    cipher_wrap.c
    cmac.c
    ctr_drbg.c
    des.c
    dhm.c
    ecdh.c
    ecdsa.c
    ecjpake.c
    ecp.c
    ecp_curves.c
    entropy.c
    entropy_poll.c
    error.c
    gcm.c
    havege.c
    hkdf.c
    hmac_drbg.c
    md.c
    md2.c
    md4.c
    md5.c
    md_wrap.c
    memory_buffer_alloc.c
    nist_kw.c
    oid.c
    padlock.c
    pem.c
    pk.c
    pk_wrap.c
    pkcs12.c
    pkcs5.c
    pkparse.c
    pkwrite.c
    platform.c
    platform_util.c
    poly1305.c
    ripemd160.c
    rsa.c
    rsa_internal.c
    sha1.c
    sha256.c
    sha512.c
    threading.c
    timing.c
    version.c
    version_features.c
    xtea.c
)

set(src_x509
    certs.c
    pkcs11.c
    x509.c
    x509_create.c
    x509_crl.c
    x509_crt.c
    x509_csr.c
    x509write_crt.c
    x509write_csr.c
)

set(src_tls
    debug.c
    net_sockets.c
    ssl_cache.c
    ssl_ciphersuites.c
    ssl_cli.c
    ssl_cookie.c
    ssl_srv.c
    ssl_ticket.c
    ssl_tls.c
)

add_library(MBEDTLS_CRYPTO_STATIC STATIC ${src_crypto} ${src_x509} ${src_tls})
target_compile_definitions(MBEDTLS_CRYPTO_STATIC PRIVATE "MBEDTLS_CONFIG_FILE\\=<config-no-tls.h>")
set_target_properties(MBEDTLS_CRYPTO_STATIC PROPERTIES OUTPUT_NAME mbedtls)
set_property(TARGET MBEDTLS_CRYPTO_STATIC PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(MBEDTLS_CRYPTO_STATIC pthread)


