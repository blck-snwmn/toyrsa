package toyrsa

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"hash"
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

func SignPKCS1v15(hash hash.Hash, n, d *big.Int, digest []byte) ([]byte, error) {
	emLen := (n.BitLen() + 7) / 8
	em, err := encodeEMSAPKCS1v15(hash, digest, emLen)
	if err != nil {
		return nil, err
	}
	return Sign(n, d, em), nil
}

func encodeEMSAPKCS1v15(hash hash.Hash, m []byte, emLen int) ([]byte, error) {
	// 1.  Apply the hash function to the message M to produce a hash
	// value H:
	//    H = Hash(M).
	// If the hash function outputs "message too long", output
	// "message too long" and stop.
	// hash.Reset()
	// hash.Write(m)
	// h := hash.Sum(nil)
	// hash.Reset()
	h := m

	// 2.  Encode the algorithm ID for the hash function and the hash
	// value into an ASN.1 value of type DigestInfo (see
	// Appendix A.2.4) with the DER, where the type DigestInfo has
	// the syntax
	// 	 DigestInfo ::= SEQUENCE {
	// 		 digestAlgorithm AlgorithmIdentifier,
	// 		 digest OCTET STRING
	// 	 }
	// The first field identifies the hash function and the second
	// contains the hash value.  Let T be the DER encoding of the
	// DigestInfo value (see the notes below), and let tLen be the
	// length in octets of T.
	tLen := len(digitingoOfSHA256) + 32
	t := make([]byte, tLen)
	copy(t, digitingoOfSHA256)
	copy(t[len(digitingoOfSHA256):], h)

	// 3.  If emLen < tLen + 11, output "intended encoded message length
	// too short" and stop.
	if emLen < tLen+11 {
		return nil, errors.New("message too long")
	}
	// 4.  Generate an octet string PS consisting of emLen - tLen - 3
	// octets with hexadecimal value 0xff.  The length of PS will be
	// at least 8 octets.
	ps := bytes.Repeat([]byte{0xff}, emLen-tLen-3)

	// 5.  Concatenate PS, the DER encoding T, and other padding to form
	// the encoded message EM as
	//    EM = 0x00 || 0x01 || PS || 0x00 || T.
	em := make([]byte, emLen)
	em[1] = 0x01
	copy(em[2:], ps)
	copy(em[3+len(ps):], t)

	// 6.  Output EM.
	return em, nil
}

// SEQUENCE=30
// OCTET STRING=04
// NULL=05 00
// AlgorithmIdentifier: https://www.rfc-editor.org/rfc/rfc5280#page-118
// OBJECT IDENTIFIER=06
//
//	DigestInfo ::= SEQUENCE {
//	  digestAlgorithm DigestAlgorithm,
//	  digest OCTET STRING
//	}
//
//	DigestAlgorithm ::= AlgorithmIdentifier {
//	  {PKCS1-v1-5DigestAlgorithms}
//	}
//
//	PKCS1-v1-5DigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
//	 { OID id-md2        PARAMETERS NULL }|
//	 { OID id-md5        PARAMETERS NULL }|
//	 { OID id-sha1       PARAMETERS NULL }|
//	 { OID id-sha224     PARAMETERS NULL }|
//	 { OID id-sha256     PARAMETERS NULL }|
//	 { OID id-sha384     PARAMETERS NULL }|
//	 { OID id-sha512     PARAMETERS NULL }|
//	 { OID id-sha512-224 PARAMETERS NULL }|
//	 { OID id-sha512-256 PARAMETERS NULL }
//	}

// 	2*40+16=96=0x60
// 	840=6*128(768)+72=0x06 48 + 0x80 = 0x86 48
// 	(0x)60 86 48 01 65 03 04 02 01
//	id-sha256    OBJECT IDENTIFIER ::= {
//	 joint-iso-itu-t (2) country (16) us (840) organization (1)
//	 gov (101) csor (3) nistalgorithm (4) hashalgs (2) 1
//	}
//

var digitingoOfSHA256 = []byte{
	// DigestInfo
	0x30, // SEQUENCE
	0x31, // length
	// digestAlgorithm
	0x30,                                                 // AlgorithmIdentifier.SEQUENCE
	0x0d,                                                 // length
	0x06,                                                 // ALGORITHM-IDENTIFIER.OBJECT IDENTIFIER
	0x09,                                                 // length
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // id-sha256
	0x05, 0x00, // NULL
	// digest
	0x04, // OCTET STRIN
	0x20, // length(sha256 hash length)
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
