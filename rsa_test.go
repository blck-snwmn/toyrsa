package toyrsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"math/big"
	"reflect"
	"testing"
)

func Test_mgf1(t *testing.T) {
	seed := []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
	db := []byte("\x9f\x86Ё\x88L}e\x9a/\xea\xa0\xc5Z\xd0\x15\xa3\xbfO\x1b+\v\x82,\xd1]l\x15\xb0\xf0\n\b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01Cozy lummox gives smart squid who asks for job pen.")

	mask, _ := mgf1(seed, sha256.New(), len(db))

	maskedDb := make([]byte, len(db))
	subtle.XORBytes(maskedDb, db, mask)

	want := []byte("\x87o8]\xc0\xb3^\x9b\xe6o\x04\xdaOmH\x16\xdaO\x8c1\n\xf9@!\xbe\xdb\xf8\xb4dn'\x810U>x\x13\xefҸs3\x94O]\x82\x9a\xb2\xea\xf2\xfa\x02r\xa4^@q\xf2lf\xb4\x9a\n\xe3ߢ\xb0:\x15#\x94\xdc坂Jb\x97~#k\x93`A\xbd\x15\xf8\xd3D\x91.\x99+\rl")
	if !reflect.DeepEqual(maskedDb, want) {
		t.Errorf("\ngot =%X,\nwant=%X\n", maskedDb, want)
	}
}

func Test_Encrypt(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)

	var (
		d = key.D
		n = key.N
		e = key.E

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)
	ciphertext := Encrypt(n, big.NewInt(int64(e)), plaintext)
	decryptPlaintext := Decrypt(n, d, ciphertext)
	if !reflect.DeepEqual(plaintext, decryptPlaintext) {
		t.Errorf("\ngot =%X,\nwant=%X\n", plaintext, decryptPlaintext)
	}
}

func Test_EncryptPKCS1v15(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)

	var (
		d = key.D
		n = key.N
		e = key.E

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)

	genReader := func(gociphertext []byte) io.Reader {
		// Use Go results.
		// Because rsa.EncryptPKCS1v15 calls randutil.MaybeReadByte, so the sequence of bytes read can change from run to run.
		x := Decrypt(n, d, gociphertext)
		x = x[2:]
		index := bytes.Index(x, []byte{0x00})
		return bytes.NewBuffer(x[0:index])
	}

	for i := 0; i < 1000; i++ {
		gociphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, plaintext)
		ciphertext, err := EncryptPKCS1v15(genReader(gociphertext), n, big.NewInt(int64(e)), plaintext)
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

func Test_EncryptOAEP(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)

	var (
		// d = key.D
		n = key.N
		e = key.E

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)
	label := []byte("test")

	reader := rand.Reader
	b := bytes.NewBuffer(nil)
	reader = io.TeeReader(reader, b)
	for i := 0; i < 1000; i++ {
		gociphertext, _ := rsa.EncryptOAEP(sha256.New(), reader, &key.PublicKey, plaintext, label)
		ciphertext, _ := EncryptOAEP(sha256.New(), b, n, big.NewInt(int64(e)), plaintext, label)
		if !reflect.DeepEqual(ciphertext, gociphertext) {
			t.Errorf("\ngot =%X,\nwant=%X", ciphertext, gociphertext)
		}
	}
}
