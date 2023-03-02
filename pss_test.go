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

func TestSignPSS(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024)

	var (
		d = key.D
		n = key.N
		e = big.NewInt(int64(key.E))

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)
	reader := rand.Reader
	b := bytes.NewBuffer(nil)
	reader = io.TeeReader(reader, b)

	hash := sha256.New()
	hash.Write(plaintext)
	digest := hash.Sum(nil)
	for i := 0; i < 1000; i++ {
		gs, err := rsa.SignPSS(reader, key, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: 10})
		if err != nil {
			t.Fatal(err)
		}
		s, err := SignPSS(sha256.New(), b, n, d, digest, 10)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(s, gs) {
			t.Errorf("\ngot =%X,\nwant=%X\n", s, gs)
		}
		err = rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest, s, &rsa.PSSOptions{SaltLength: 10})
		if err != nil {
			t.Fatal(err)
		}
		err = VerifyPSS(sha256.New(), n, e, digest, s, 10)
		if err != nil {
			t.Fatal(err)
		}
	}
}
