package toyrsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"
	"reflect"
	"testing"
)

func Test_EncryptPKCS1v15(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024)

	var (
		d = key.D
		n = key.N
		e = big.NewInt(int64(key.E))

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)

	genReader := func(gociphertext []byte) io.Reader {
		// Use Go results.
		// Because rsa.EncryptPKCS1v15 calls randutil.MaybeReadByte, so the sequence of bytes read can change from run to run.
		x := decrypt(n, d, gociphertext)
		x = x[2:]
		index := bytes.Index(x, []byte{0x00})
		return bytes.NewBuffer(x[0:index])
	}

	for i := 0; i < 1000; i++ {
		gociphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plaintext)
		ciphertext, err := EncryptPKCS1v15(genReader(gociphertext), n, e, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ciphertext, gociphertext) {
			t.Errorf("\ngot =%X,\nwant=%X\n", ciphertext, gociphertext)
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
