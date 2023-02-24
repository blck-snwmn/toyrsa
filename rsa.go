package toyrsa

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/big"
)

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
	em := Decrypt(n, d, ciphertext)

	valid0 := subtle.ConstantTimeByteEq(em[0], 0) == 1
	valid1 := subtle.ConstantTimeByteEq(em[1], 2) == 1
	em = em[2:]
	index := bytes.Index(em, []byte{0x00}) // no constant time
	valid := index != -1 && valid0 && valid1
	if !valid {
		return nil, errors.New("invalid data")
	}
	return em[index+1:], nil
}

func EncryptOAEP(hash hash.Hash, random io.Reader, n, e *big.Int, plaintext, label []byte) ([]byte, error) {
	hash.Reset()

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	k := (n.BitLen() + 7) / 8
	em := make([]byte, k)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	copy(db[:hash.Size()], lHash)

	db[len(db)-len(plaintext)-1] = 0x01
	copy(db[len(db)-len(plaintext):], plaintext)

	_, err := random.Read(seed)
	if err != nil {
		return nil, err
	}
	mgf1xor(db, seed, hash)
	mgf1xor(seed, db, hash)

	return Encrypt(n, e, em), nil
}

func DecryptOAEP(hash hash.Hash, random io.Reader, n, d *big.Int, ciphertext, label []byte) ([]byte, error) {
	em := Decrypt(n, d, ciphertext)

	hash.Reset()
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1xor(seed, db, hash)
	mgf1xor(db, seed, hash)

	isSameHash := subtle.ConstantTimeCompare(db[:hash.Size()], lHash) == 1

	db = db[hash.Size():]
	index := bytes.Index(db, []byte{0x01}) // no constant time
	valid := index != -1 && isSameHash && subtle.ConstantTimeByteEq(em[0], 0x00) == 1
	if !valid {
		return nil, errors.New("invalid data")
	}
	return db[index+1:], nil
}

func Encrypt(n, e *big.Int, plaintext []byte) []byte {
	o := make([]byte, len(plaintext))
	x := new(big.Int)
	x = x.SetBytes(plaintext).Mod(x, n)
	x = x.Exp(x, e, n)
	r := x.Bytes()
	copy(o[len(o)-len(r):], r)
	return o
}

func Decrypt(n, d *big.Int, ciphertext []byte) []byte {
	o := make([]byte, len(ciphertext))
	x := new(big.Int)
	x = x.SetBytes(ciphertext).Mod(x, n)
	x = x.Exp(x, d, n)
	r := x.Bytes()
	copy(o[len(o)-len(r):], r)
	return o
}

func mgf1xor(out, seed []byte, hash hash.Hash) {

	hLen := hash.Size()

	counter := uint32(0)
	counterBuf := make([]byte, 4)

	var buf []byte

	for len(out) > 0 {
		binary.BigEndian.PutUint32(counterBuf, counter)
		hash.Reset()
		hash.Write(seed)
		hash.Write(counterBuf)
		h := hash.Sum(buf[:0])
		subtle.XORBytes(out, out, h)

		consumeLen := hLen
		if len(out) < consumeLen {
			consumeLen = len(out)
		}
		out = out[consumeLen:]
		counter++
	}
	return
}
