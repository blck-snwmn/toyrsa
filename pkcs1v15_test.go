package toyrsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
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

	for i := 0; i < 1000; i++ {
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
