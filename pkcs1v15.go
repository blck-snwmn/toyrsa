package toyrsa

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

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
