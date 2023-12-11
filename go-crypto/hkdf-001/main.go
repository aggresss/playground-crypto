package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

func getSalt(n int) []byte {
	nonce := make([]byte, n)
	// if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	// 	panic(err.Error())
	// }
	for i := 0; i < len(nonce); i++ {
		nonce[i] = 0xF0
	}
	return (nonce)
}
func main() {
	hash := sha256.New
	s := "The quick brown fox jumps over the lazy dog"
	salt := getSalt(hash().Size())
	info := []byte("")
	argCount := len(os.Args[1:])
	if argCount > 0 {
		s = os.Args[1]
	}

	secret := []byte(s)
	kdf := hkdf.New(hash, secret, salt, info)

	key1 := make([]byte, 16)
	_, _ = io.ReadFull(kdf, key1)
	fmt.Printf("Secret: %s\n", s)
	fmt.Printf("HKDF 16 byte key: %x\n", key1)

	key2 := make([]byte, 32)
	_, _ = io.ReadFull(kdf, key2)
	fmt.Printf("HKDF 32 byte key: %x\n", key2)

	key3 := make([]byte, 32)
	_, _ = io.ReadFull(kdf, key3)
	fmt.Printf("HKDF 32 byte key: %x\n", key3)
}
