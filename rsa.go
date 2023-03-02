package toyrsa

import (
	"crypto/subtle"
	"encoding/binary"
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

func Encrypt(n, e *big.Int, plaintext []byte) []byte {
	return encrypt(n, e, plaintext)
}

func Verify(n, e *big.Int, plaintext []byte) []byte {
	return encrypt(n, e, plaintext)
}

func Decrypt(n, d *big.Int, ciphertext []byte) []byte {
	return decrypt(n, d, ciphertext)
}

func Sign(n, d *big.Int, ciphertext []byte) []byte {
	return decrypt(n, d, ciphertext)
}

func encrypt(n, e *big.Int, plaintext []byte) []byte {
	o := make([]byte, len(plaintext))
	x := new(big.Int)
	x = x.SetBytes(plaintext).Mod(x, n)
	x = x.Exp(x, e, n)
	r := x.Bytes()
	copy(o[len(o)-len(r):], r)
	return o
}

func decrypt(n, d *big.Int, ciphertext []byte) []byte {
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
}
