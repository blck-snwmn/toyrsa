package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"reflect"

	"github.com/blck-snwmn/toyrsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint: gosec // toy implementation

	var (
		d = key.D
		n = key.N
		e = key.E

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)
	fmt.Println(key.PublicKey.Size())

	{
		ciphertext := toyrsa.Encrypt(n, big.NewInt(int64(e)), plaintext)
		fmt.Printf("%X\n", plaintext)
		decryptPlaintext := toyrsa.Decrypt(n, d, ciphertext)
		fmt.Printf("%X\n", decryptPlaintext)
		fmt.Printf("%t\n", reflect.DeepEqual(plaintext, decryptPlaintext))

	}
	{
		dummy := bytes.Repeat([]byte{0xFF}, 128)
		gociphertext, _ := rsa.EncryptPKCS1v15(bytes.NewBuffer(dummy), &key.PublicKey, plaintext)
		fmt.Printf("%X\n", gociphertext)

		ciphertext, _ := toyrsa.EncryptPKCS1v15(bytes.NewBuffer(dummy), n, big.NewInt(int64(e)), plaintext)
		fmt.Printf("%X\n", ciphertext)
		d, err := toyrsa.DecryptPKCS1v15(n, d, ciphertext)
		fmt.Println(err)
		fmt.Printf("%X\n", d)
	}
	{
		label := []byte("test")
		dummy := bytes.Repeat([]byte{0xFF}, 128)
		gociphertext, _ := rsa.EncryptOAEP(sha256.New(), bytes.NewBuffer(dummy), &key.PublicKey, plaintext, label)
		fmt.Printf("%X\n", gociphertext)

		ciphertext, _ := toyrsa.EncryptOAEP(sha256.New(), bytes.NewBuffer(dummy), n, big.NewInt(int64(e)), plaintext, label)
		fmt.Printf("%X\n", ciphertext)
	}
}
