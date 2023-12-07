package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func encrypt(plaintext, key, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext
}

func decrypt(ciphertext, key, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func main() {
	fmt.Println("AES encryption with GCM")
	plaintext := []byte("Some plain text")
	key := []byte("secretkey32bytessecretkey32bytes")
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := encrypt(plaintext, key, nonce)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	recoveredPt := decrypt(ciphertext, key, nonce)
	fmt.Printf("Recovered plaintext: %s\n", recoveredPt)
}
