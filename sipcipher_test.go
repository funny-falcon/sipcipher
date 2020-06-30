package sipcipher_test

import (
	"crypto/aes"
	"crypto/cipher"
	mathrand "math/rand"
	"testing"

	"github.com/funny-falcon/sipcipher"
)

var key [16]byte
var nonce [12]byte
var plaintext [4096]byte
var dumb []byte

func init() {
	mathrand.Read(key[:])
	mathrand.Read(nonce[:])
	mathrand.Read(plaintext[:])
}

func Benchmark_SipCipher_32byte(b *testing.B) {
	for n := 0; n < b.N; n++ {
		dumb = sipcipher.Seal(key[:], nonce[:], plaintext[:32])
	}
}

func Benchmark_AESGCM_32byte(b *testing.B) {
	ci, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(ci)
	for n := 0; n < b.N; n++ {
		dumb = gcm.Seal(nil, nonce[:], plaintext[:32], nil)
	}
}

func Benchmark_SipCipher_121byte(b *testing.B) {
	for n := 0; n < b.N; n++ {
		dumb = sipcipher.Seal(key[:], nonce[:], plaintext[:121])
	}
}

func Benchmark_AESGCM_121byte(b *testing.B) {
	ci, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(ci)
	for n := 0; n < b.N; n++ {
		dumb = gcm.Seal(nil, nonce[:], plaintext[:121], nil)
	}
}

func Benchmark_SipCipher_1021byte(b *testing.B) {
	for n := 0; n < b.N; n++ {
		dumb = sipcipher.Seal(key[:], nonce[:], plaintext[:1021])
	}
}

func Benchmark_AESGCM_1021byte(b *testing.B) {
	ci, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(ci)
	for n := 0; n < b.N; n++ {
		dumb = gcm.Seal(nil, nonce[:], plaintext[:1021], nil)
	}
}

func Benchmark_SipCipher_4020byte(b *testing.B) {
	for n := 0; n < b.N; n++ {
		dumb = sipcipher.Seal(key[:], nonce[:], plaintext[:4020])
	}
}

func Benchmark_AESGCM_4020byte(b *testing.B) {
	ci, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(ci)
	for n := 0; n < b.N; n++ {
		dumb = gcm.Seal(nil, nonce[:], plaintext[:4020], nil)
	}
}
