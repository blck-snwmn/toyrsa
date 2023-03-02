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

func SignPSS(hash hash.Hash, random io.Reader, n, d *big.Int, digest []byte, saltLen int) ([]byte, error) {
	salt := make([]byte, saltLen)
	_, err := random.Read(salt)
	if err != nil {
		return nil, err
	}
	em, err := encodeEMSAPSS(hash, digest, salt, n.BitLen()-1)
	if err != nil {
		return nil, err
	}
	return Sign(n, d, em), nil
}

func VerifyPSS(hash hash.Hash, n, e *big.Int, digest, signature []byte, saltLen int) error {
	em := encrypt(n, e, signature)
	return verifyEMSAPSS(hash, digest, em, saltLen, n.BitLen()-1)
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

func encodeEMSAPSS(hash hash.Hash, mHash, salt []byte, emBits int) ([]byte, error) {
	// See RFC 8017, Section 9.1.1.

	emLen := (emBits + 7) / 8
	sLen := len(salt)
	if emLen < hash.Size()+sLen+2 {
		return nil, errors.New("encoding error")
	}

	hash.Reset()

	// 5. Let
	//      M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//    M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
	// 6.   Let H = Hash(M'), an octet string of length hLen.
	hash.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	hash.Write(mHash)
	hash.Write(salt)
	h := hash.Sum(nil)
	hash.Reset()

	em := make([]byte, emLen)

	db := em[:emLen-hash.Size()-1]
	db[len(db)-sLen-1] = 0x01
	copy(db[len(db)-sLen:], salt)

	// 9.   Let dbMask = MGF(H, emLen - hLen - 1).
	// 10.  Let maskedDB = DB \xor dbMask.
	mgf1xor(db, h, hash)
	// 11.  Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
	db[0] &= byte(0xFF >> (8*emLen - emBits))

	// 12.  Let EM = maskedDB || H || 0xbc.
	head := em[len(db):]
	copy(head, h)
	head = head[len(h):]
	head[0] = 0xbc

	// 13.  Output EM.
	return em, nil
}

var errVerification = errors.New("inconsistent")

func verifyEMSAPSS(hash hash.Hash, mHash, em []byte, sLen, emBits int) error {
	emLen := (emBits + 7) / 8
	if emLen != len(em) {
		return errVerification
	}
	// 1.   If the length of M is greater than the input limitation for
	// the hash function (2^61 - 1 octets for SHA-1), output
	// "inconsistent" and stop.
	if hash.Size() < len(mHash) {
		return errVerification
	}
	// 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
	if emLen < hash.Size()+sLen+2 {
		return errVerification
	}
	// 4.   If the rightmost octet of EM does not have hexadecimal value
	// 0xbc, output "inconsistent" and stop.
	if subtle.ConstantTimeByteEq(em[len(em)-1], 0xbc) == 0 {
		return errVerification
	}
	// 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
	// and let H be the next hLen octets.
	db := em[:emLen-hash.Size()-1]
	h := em[emLen-hash.Size()-1 : emLen-1]

	// 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
	// maskedDB are not all equal to zero, output "inconsistent" and
	// stop.
	mask := ^(0xFF >> (8*emLen - emBits))
	if subtle.ConstantTimeByteEq(db[0]&uint8(mask), 0x00) == 0 {
		return errVerification
	}

	// 7.   Let dbMask = MGF(H, emLen - hLen - 1).
	// 8.   Let DB = maskedDB \xor dbMask.
	mgf1xor(db, h, hash)

	// 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
	// in DB to zero.
	db[0] &= byte(0xFF >> (8*emLen - emBits))

	// 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
	// zero or if the octet at position emLen - hLen - sLen - 1 (the
	// leftmost position is "position 1") does not have hexadecimal
	// value 0x01, output "inconsistent" and stop.
	if subtle.ConstantTimeCompare(db[:len(db)-sLen-1], make([]byte, len(db)-sLen-1)) == 0 {
		return errVerification
	}
	if subtle.ConstantTimeByteEq(db[len(db)-sLen-1], 0x01) == 0 {
		return errVerification
	}
	// 11.  Let salt be the last sLen octets of DB.
	salt := db[len(db)-sLen:]

	// 12. Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	hash.Reset()
	hash.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	hash.Write(mHash)
	hash.Write(salt)
	hh := hash.Sum(nil)
	hash.Reset()
	if subtle.ConstantTimeCompare(h, hh) == 0 {
		return errVerification
	}

	return nil
}
