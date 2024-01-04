package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"
	TLS_AES_256_GCM_SHA384       = "TLS_AES_256_GCM_SHA384"
	TLS_AES_128_GCM_SHA256       = "TLS_AES_128_GCM_SHA256"
)

func main() {
	key := make([]byte, 32)

	aead0, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	fmt.Println(TLS_CHACHA20_POLY1305_SHA256, ":", aead0.Overhead())

	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead1, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}
	fmt.Println(TLS_AES_256_GCM_SHA384, ":", aead1.Overhead())
}
