package toyrsa

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

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
