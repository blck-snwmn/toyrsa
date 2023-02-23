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
	// no constant time
	em := Decrypt(n, d, ciphertext)
	if em[0] != 0 {
		return nil, errors.New("invalid value(index=0)")
	}
	if em[1] != 2 {
		return nil, errors.New("invalid value(index=1)")
	}
	em = em[2:]
	index := bytes.Index(em, []byte{0x00})
	if index == -1 {
		return nil, errors.New("invalid data(no 0x00)")
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
	err = mgf1xor(db, seed, hash)
	if err != nil {
		return nil, err
	}

	err = mgf1xor(seed, db, hash)
	if err != nil {
		return nil, err
	}

	return Encrypt(n, e, em), nil
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

func mgf1xor(out, seed []byte, hash hash.Hash) error {
	maskLen := len(out)
	hLen := hash.Size()
	counter := uint32(0)

	counterBuf := make([]byte, 4)

	t := make([]byte, maskLen)
	head := t

	for len(head) > 0 {
		binary.BigEndian.PutUint32(counterBuf, counter)
		hash.Reset()
		hash.Write(seed)
		hash.Write(counterBuf)
		g := hash.Sum(nil)
		copy(head, g)

		consumeLen := hLen
		if len(head) < consumeLen {
			consumeLen = len(head)
		}
		subtle.XORBytes(out, out, head[:consumeLen])

		out = out[consumeLen:]
		head = head[consumeLen:]
		counter++
	}
	return nil
}
