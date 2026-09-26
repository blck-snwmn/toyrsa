package toyrsa

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
)

// openSSLVectorModulus is the public modulus of test512Key in Go's rsa_test.go.
const openSSLVectorModulus = "b2990f49c47dfa8cd400ae6a4d1b8a3b6a13642b23f28b003bfb97790ade9a4cc82b8b2a81747ddec08b6296e53a08c331687ef25c4bf4936ba1c0e6041e9d15"

func TestEncryptPKCS1v15OpenSSLVectors(t *testing.T) {
	// Ciphertexts are OpenSSL-generated vectors from
	// https://go.dev/src/crypto/rsa/pkcs1v15_test.go.
	// The padding was recovered from the matching test512Key.
	n, ok := new(big.Int).SetString(openSSLVectorModulus, 16)
	if !ok {
		t.Fatal("invalid test modulus")
	}
	e := big.NewInt(65537)

	tests := []struct {
		name       string
		plaintext  string
		paddingHex string
		ciphertext string
	}{
		{
			name:       "one byte",
			plaintext:  "x",
			paddingHex: "9028be2a51edead378d3a1a252fe402f8528adcdb868ce5c225b883a86b4e48720b59723f9da6e8f4be735ff26590ce666c0d4e5ba9784c1f2fd53f3",
			ciphertext: "gIcUIoVkD6ATMBk/u/nlCZCCWRKdkfjCgFdo35VpRXLduiKXhNz1XupLLzTXAybEq15juc+EgY5o0DHv/nt3yg==",
		},
		{
			name:       "short message",
			plaintext:  "testing.",
			paddingHex: "9b3343d221b7f422d0e9aaff04bd28132dd1ea09a220c5f4be0ae5a00f7f5dbd3f9f7157e23e8d34e822865024be7615d7a47a3b78",
			ciphertext: "Y7TOCSqofGhkRb+jaVRLzK8xw2cSo1IVES19utzv6hwvx+M8kFsoWQm5DzBeJCZTCVDPkTpavUuEbgp8hnUGDw==",
		},
		{
			name:       "message with newline",
			plaintext:  "testing.\n",
			paddingHex: "01e737ea7d8d3bf256802a1bda02c89c96d4b36a6eb066ab4bd979e466755fda437ac112d104f10f139955226c500a2eabcca5df",
			ciphertext: "arReP9DJtEVyV2Dg3dDp4c/PSk1O6lxkoJ8HcFupoRorBZG+7+1fDAwT1olNddFnQMjmkb8vxwmNMoTAT/BFjQ==",
		},
		{
			name:       "maximum message length",
			plaintext:  "01234567890123456789012345678901234567890123456789012",
			paddingHex: "a6dc3466baac7eb7",
			ciphertext: "WtaBXIoGC54+vH0NH0CHHE+dRDOsMc/6BrfFu2lEqcKL9+uDuWaf+Xj9mrbQCjjZcpQuX733zyok/jsnqe/Ftw==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padding, err := hex.DecodeString(tt.paddingHex)
			if err != nil {
				t.Fatal(err)
			}
			if len(padding) != (n.BitLen()+7)/8-len(tt.plaintext)-3 {
				t.Fatal("invalid padding length in test vector")
			}
			want, err := base64.StdEncoding.DecodeString(tt.ciphertext)
			if err != nil {
				t.Fatal(err)
			}

			got, err := EncryptPKCS1v15(bytes.NewReader(padding), n, e, []byte(tt.plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("ciphertext = %x, want %x", got, want)
			}
		})
	}
}

func TestEncryptPKCS1v15PlaintextLength(t *testing.T) {
	n, ok := new(big.Int).SetString(openSSLVectorModulus, 16)
	if !ok {
		t.Fatal("invalid test modulus")
	}
	k := (n.BitLen() + 7) / 8
	e := big.NewInt(65537)

	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{name: "empty", length: 0},
		{name: "maximum", length: k - 11},
		{name: "one byte too long", length: k - 10, wantErr: true},
		{name: "no padding", length: k - 3, wantErr: true},
		{name: "no room for header", length: k - 2, wantErr: true},
		{name: "longer than modulus", length: k + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := bytes.Repeat([]byte{'x'}, tt.length)
			padding := bytes.NewReader(bytes.Repeat([]byte{0xff}, k))
			ciphertext, err := EncryptPKCS1v15(padding, n, e, plaintext)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %d-byte plaintext", tt.length)
				}
				if ciphertext != nil {
					t.Fatalf("ciphertext = %x, want nil on error", ciphertext)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) != k {
				t.Fatalf("ciphertext length = %d, want %d", len(ciphertext), k)
			}
		})
	}
}
