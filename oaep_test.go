package toyrsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"math/big"
	"reflect"
	"testing"
)

func Test_EncryptOAEP(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint: gosec // toy implementation

	var (
		d = key.D
		n = key.N
		e = big.NewInt(int64(key.E))

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)
	label := []byte("test")

	reader := rand.Reader
	b := bytes.NewBuffer(nil)
	reader = io.TeeReader(reader, b)
	for i := 0; i < 1000; i++ {
		gociphertext, _ := rsa.EncryptOAEP(sha256.New(), reader, &key.PublicKey, plaintext, label)
		ciphertext, _ := EncryptOAEP(sha256.New(), b, n, e, plaintext, label)
		if !reflect.DeepEqual(ciphertext, gociphertext) {
			t.Errorf("\ngot =%X,\nwant=%X", ciphertext, gociphertext)
		}
		decryptPlaintext, err := DecryptOAEP(sha256.New(), nil, n, d, ciphertext, label)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(plaintext, decryptPlaintext) {
			t.Errorf("\ngot =%X,\nwant=%X\n", plaintext, decryptPlaintext)
		}
	}
}
