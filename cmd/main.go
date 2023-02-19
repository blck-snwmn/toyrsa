package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"reflect"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)

	var (
		d = key.D
		n = key.N
		e = key.E

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)

	// crypto
	ciphertext := Crypto(n, big.NewInt(int64(e)), plaintext)
	fmt.Printf("%X\n", plaintext)
	decryptPlaintext := Decrypt(n, d, ciphertext)
	fmt.Printf("%X\n", decryptPlaintext)
	fmt.Printf("%t\n", reflect.DeepEqual(plaintext, decryptPlaintext))
}

func Crypto(n, e *big.Int, plaintext []byte) []byte {
	x := new(big.Int)
	x = x.SetBytes(plaintext).Mod(x, n)
	x = x.Exp(x, e, n)
	return x.Bytes()
}

func Decrypt(n, d *big.Int, ciphertext []byte) []byte {
	x := new(big.Int)
	x = x.SetBytes(ciphertext).Mod(x, n)
	x = x.Exp(x, d, n)
	return x.Bytes()
}
