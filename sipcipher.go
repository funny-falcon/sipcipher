package sipcipher

import (
	"encoding/binary"
	"math/bits"
	"unsafe"
)

const delta = uint64(0x9e3779b97f4a7c15)
const passes = 3

func Seal(key, nonce, plaintext []byte) (ciphertext []byte) {
	k1, k2 := bytesTo2U64(key)
	n1, n2 := bytesTo2U64(nonce)
	p64 := bytesToU64s(plaintext, 24, 9)
	lp64 := len(p64)
	gamma := uint64(0)
	nix := 0
	for n := 0; n < passes; n++ {
		left := p64[lp64-1]
		for i := range p64 {
			var right uint64
			if i < lp64-1 {
				right = p64[i+1]
			} else {
				right = p64[0]
			}
			var p uint64
			{
				v1, v3 := left, right
				v0 := k1 ^ (gamma + n1)
				v2 := k2 ^ (gamma + n2)

				v0 += v1
				v2 += v3
				v1 = bits.RotateLeft64(v1, 13)
				v3 = bits.RotateLeft64(v3, 16)
				v1 ^= v0
				v3 ^= v2
				v0 = bits.RotateLeft64(v0, 32)
				v2 += v1
				v0 += v3
				v1 = bits.RotateLeft64(v1, 17)
				v3 = bits.RotateLeft64(v3, 21)
				v1 ^= v2
				v3 ^= v0
				//v2 = bits.RotateLeft64(v2, 32)

				p = v1 + v3
			}
			p64[i] ^= p
			left = p64[i]
			gamma += delta
			nix++
			n1, n2 = n2, n1
			k1 = bits.RotateLeft64(k1, 3)
			k2 = bits.RotateLeft64(k2, 5)
		}
	}
	res := u64sToBytes(p64)
	return res
}

func Open(key, nonce, ciphertext []byte) (plaintext []byte) {
	k1, k2 := bytesTo2U64(key)
	n1, n2 := bytesTo2U64(nonce)
	p64 := bytesToU64s(ciphertext, 0, 0)
	lp64 := len(p64)
	nix := lp64 * passes
	if nix&1 != 0 {
		n1, n2 = n2, n1
	}
	k1 = bits.RotateLeft64(k1, (nix*3)&63)
	k2 = bits.RotateLeft64(k2, (nix*5)&63)
	gamma := delta * uint64(nix)
	for nix > 0 {
		right := p64[0]
		for i := lp64 - 1; i >= 0; i-- {
			nix--
			gamma -= delta
			n1, n2 = n2, n1
			var left uint64
			if i > 0 {
				left = p64[i-1]
			} else {
				left = p64[lp64-1]
			}
			k1 = bits.RotateLeft64(k1, 64-3)
			k2 = bits.RotateLeft64(k2, 64-5)
			var p uint64
			{
				v1, v3 := left, right
				v0 := k1 ^ (gamma + n1)
				v2 := k2 ^ (gamma + n2)

				v0 += v1
				v2 += v3
				v1 = bits.RotateLeft64(v1, 13)
				v3 = bits.RotateLeft64(v3, 16)
				v1 ^= v0
				v3 ^= v2
				v0 = bits.RotateLeft64(v0, 32)
				v2 += v1
				v0 += v3
				v1 = bits.RotateLeft64(v1, 17)
				v3 = bits.RotateLeft64(v3, 21)
				v1 ^= v2
				v3 ^= v0
				//v2 = bits.RotateLeft64(v2, 32)

				p = v1 + v3
			}
			p64[i] ^= p
			right = p64[i]
		}
	}
	buf := u64sToBytes(p64)
	padlen := int(buf[len(buf)-1])
	if padlen > len(buf) {
		panic("NO")
	}
	sum := uint32(0)
	for _, x := range buf[len(buf)-padlen : len(buf)-1] {
		sum += uint32(x)
	}
	if sum != 0 {
		panic("NO")
	}
	return buf[:len(buf)-int(buf[len(buf)-1])]
}

func bytesTo2U64(b []byte) (r1, r2 uint64) {
	var t [16]byte
	copy(t[:], b)
	if len(b) < 16 {
		t[15] = byte(16 - len(b))
	}
	r1 = binary.LittleEndian.Uint64(t[:])
	r2 = binary.LittleEndian.Uint64(t[8:])
	return r1, r2
}

func bytesToU64s(b []byte, minsize, minpad int) (res []uint64) {
	sz := len(b) + minpad
	if sz < minsize {
		sz = minsize
	}
	sz = (sz + 7) &^ 7
	br := make([]byte, sz)
	copy(br, b)
	if sz > len(b) {
		br[sz-1] = byte(sz - len(b))
	}
	bh := (*sliceHeader)(unsafe.Pointer(&br))
	rh := (*sliceHeader)(unsafe.Pointer(&res))
	*rh = *bh
	rh.len >>= 3
	rh.capa >>= 3
	return res
}

type sliceHeader struct {
	data *byte
	len  uintptr
	capa uintptr
}

func u64sToBytes(u []uint64) (b []byte) {
	uh := (*sliceHeader)(unsafe.Pointer(&u))
	bh := (*sliceHeader)(unsafe.Pointer(&b))
	*bh = *uh
	bh.len *= 8
	bh.capa *= 8
	return
}
