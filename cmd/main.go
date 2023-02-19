package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
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
	fmt.Println(key.PublicKey.Size())

	{
		ciphertext := Encrypt(n, big.NewInt(int64(e)), plaintext)
		fmt.Printf("%X\n", plaintext)
		decryptPlaintext := Decrypt(n, d, ciphertext)
		fmt.Printf("%X\n", decryptPlaintext)
		fmt.Printf("%t\n", reflect.DeepEqual(plaintext, decryptPlaintext))

	}
	{
		dummy := bytes.Repeat([]byte{0xFF}, 128)
		gociphertext, _ := rsa.EncryptPKCS1v15(bytes.NewBuffer(dummy), &key.PublicKey, plaintext)
		fmt.Printf("%X\n", gociphertext)

		ciphertext, _ := EncryptPKCS1v15(bytes.NewBuffer(dummy), n, big.NewInt(int64(e)), plaintext)
		fmt.Printf("%X\n", ciphertext)
		d, err := DecryptPKCS1v15(n, d, ciphertext)
		fmt.Println(err)
		fmt.Printf("%X\n", d)
	}
}

func fillNonZeroBytes(random io.Reader, buf []byte) error {
	for i := range buf {
		for buf[i] == 0 {
			_, err := random.Read(buf[i : i+1])
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func EncryptPKCS1v15(random io.Reader, n, e *big.Int, plaintext []byte) ([]byte, error) {
	k := (n.BitLen() + 7) / 8
	em := make([]byte, k)
	em[1] = 2
	err := fillNonZeroBytes(random, em[2:k-len(plaintext)-1]) // -1 is 0x00
	if err != nil {
		return nil, err
	}

	copy(em[k-len(plaintext):], plaintext)
	return Encrypt(n, e, em), nil
}

func DecryptPKCS1v15(n, d *big.Int, ciphertext []byte) ([]byte, error) {
	// no constant time
	em := Decrypt(n, d, ciphertext)
	if em[0] == 0 {
		return nil, errors.New("invalid value(index=0)")
	}
	if em[1] == 2 {
		return nil, errors.New("invalid value(index=1)")
	}
	index := bytes.Index(em, []byte{0x00})
	if index == -1 {
		return nil, errors.New("invalid data(no 0x00)")
	}
	return em[index+1:], nil
}

func Encrypt(n, e *big.Int, plaintext []byte) []byte {
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
