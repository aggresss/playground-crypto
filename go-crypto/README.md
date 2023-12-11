


https://pkg.go.dev/crypto

Directory | Description
--|--
aes      | Package aes implements AES encryption (formerly Rijndael), as defined in U.S. Federal Information Processing Standards Publication 197.
cipher   | Package cipher implements standard block cipher modes that can be wrapped around low-level block cipher implementations.
des      | Package des implements the Data Encryption Standard (DES) and the Triple Data Encryption Algorithm (TDEA) as defined in U.S. Federal Information Processing Standards Publication 46-3.
dsa      | Package dsa implements the Digital Signature Algorithm, as defined in FIPS 186-3.
ecdh     | Package ecdh implements Elliptic Curve Diffie-Hellman over NIST curves and Curve25519.
ecdsa    | Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as defined in FIPS 186-4 and SEC 1, Version 2.0.
ed25519  | Package ed25519 implements the Ed25519 signature algorithm.
elliptic | Package elliptic implements the standard NIST P-224, P-256, P-384, and P-521 elliptic curves over prime fields.
hmac     | Package hmac implements the Keyed-Hash Message Authentication Code (HMAC) as defined in U.S. Federal Information Processing Standards Publication 198.
md5      | Package md5 implements the MD5 hash algorithm as defined in RFC 1321.
rand     | Package rand implements a cryptographically secure random number generator.
rc4      | Package rc4 implements RC4 encryption, as defined in Bruce Schneier's Applied Cryptography.
rsa      | Package rsa implements RSA encryption as specified in PKCS #1 and RFC 8017.
sha1     | Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.
sha256   | Package sha256 implements the SHA224 and SHA256 hash algorithms as defined in FIPS 180-4.
sha512   | Package sha512 implements the SHA-384, SHA-512, SHA-512/224, and SHA-512/256 hash algorithms as defined in FIPS 180-4.
subtle   | Package subtle implements functions that are often useful in cryptographic code but require careful thought to use correctly.
tls      | Package tls partially implements TLS 1.2, as specified in RFC 5246, and TLS 1.3, as specified in RFC 8446.
x509     | Package x509 implements a subset of the X.509 standard.

https://pkg.go.dev/encoding

Directory | Description
--|--
ascii85 | Package ascii85 implements the ascii85 data encoding as used in the btoa tool and Adobe's PostScript and PDF document formats.
asn1    | Package asn1 implements parsing of DER-encoded ASN.1 data structures, as defined in ITU-T Rec X.690.
base32  | Package base32 implements base32 encoding as specified by RFC 4648.
base64  | Package base64 implements base64 encoding as specified by RFC 4648.
binary  | Package binary implements simple translation between numbers and byte sequences and encoding and decoding of varints.
csv     | Package csv reads and writes comma-separated values (CSV) files.
gob     | Package gob manages streams of gobs - binary values exchanged between an Encoder (transmitter) and a Decoder (receiver).
hex     | Package hex implements hexadecimal encoding and decoding.
json    | Package json implements encoding and decoding of JSON as defined in RFC 7159.
pem     | Package pem implements the PEM data encoding, which originated in Privacy Enhanced Mail.
xml     | Package xml implements a simple XML 1.0 parser that understands XML name spaces.