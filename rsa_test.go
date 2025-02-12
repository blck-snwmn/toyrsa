package toyrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"reflect"
	"testing"
)

func Test_mgf1(t *testing.T) {
	t.Parallel()
	seed := []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
	db := []byte("\x9f\x86Ё\x88L}e\x9a/\xea\xa0\xc5Z\xd0\x15\xa3\xbfO\x1b+\v\x82,\xd1]l\x15\xb0\xf0\n\b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01Cozy lummox gives smart squid who asks for job pen.")

	mgf1xor(db, seed, sha256.New())

	want := []byte("\x87o8]\xc0\xb3^\x9b\xe6o\x04\xdaOmH\x16\xdaO\x8c1\n\xf9@!\xbe\xdb\xf8\xb4dn'\x810U>x\x13\xefҸs3\x94O]\x82\x9a\xb2\xea\xf2\xfa\x02r\xa4^@q\xf2lf\xb4\x9a\n\xe3ߢ\xb0:\x15#\x94\xdc坂Jb\x97~#k\x93`A\xbd\x15\xf8\xd3D\x91.\x99+\rl")
	if !reflect.DeepEqual(db, want) {
		t.Errorf("\ngot =%X,\nwant=%X\n", db, want)
	}
}

func Test_Encrypt(t *testing.T) {
	t.Skip()
	key, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint: gosec // toy implementation

	var (
		d = key.D
		n = key.N
		e = big.NewInt(int64(key.E))

		plaintext = []byte("Cozy lummox gives smart squid who asks for job pen.")
	)
	ciphertext := encrypt(n, e, plaintext)
	decryptPlaintext := decrypt(n, d, ciphertext)
	if !reflect.DeepEqual(plaintext, decryptPlaintext) {
		t.Errorf("\ngot =%X,\nwant=%X\n", plaintext, decryptPlaintext)
	}
}
