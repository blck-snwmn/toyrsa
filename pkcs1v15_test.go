package toyrsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"reflect"
	"testing"
)

func Test_EncryptPKCS1v15(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint: gosec // toy implementation

	var (
		d = key.D
		n = key.N
		e = big.NewInt(int64(key.E))

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)

	for range 1000 {
		ciphertext, err := EncryptPKCS1v15(rand.Reader, n, e, plaintext)
		if err != nil {
			t.Fatal(err)
		}

		// Check the encoded message independently of the PKCS#1 v1.5 decoder.
		em := new(big.Int).Exp(new(big.Int).SetBytes(ciphertext), d, n).FillBytes(make([]byte, key.Size()))
		separator := len(em) - len(plaintext) - 1
		if em[0] != 0 || em[1] != 2 || em[separator] != 0 || !bytes.Equal(em[separator+1:], plaintext) {
			t.Fatalf("invalid encoded message: %X", em)
		}
		for _, b := range em[2:separator] {
			if b == 0 {
				t.Fatalf("zero byte in padding: %X", em)
			}
		}

		decryptPlaintext, err := DecryptPKCS1v15(n, d, ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(plaintext, decryptPlaintext) {
			t.Errorf("\ngot =%X,\nwant=%X\n", plaintext, decryptPlaintext)
		}
	}
}

func Test_SignPKCS1v15(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint: gosec // toy implementation

	var (
		d = key.D
		n = key.N
		e = big.NewInt(int64(key.E))

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)
	hash := sha256.New()
	hash.Write(plaintext)
	digest := hash.Sum(nil)

	for range 1000 {
		gs, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest)
		if err != nil {
			t.Fatal(err)
		}
		s, err := SignPKCS1v15(sha256.New(), n, d, digest)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(s, gs) {
			t.Errorf("\ngot =%X,\nwant=%X\n", s, gs)
		}
		err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, s)
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyPKCS1v15(sha256.New(), n, e, digest, s)
		if err != nil {
			t.Fatal(err)
		}
	}
}
