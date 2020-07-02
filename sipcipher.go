package sipcipher

import (
	"encoding/binary"
	"math/bits"
	"unsafe"
)

const delta = uint64(0x9e3779b97f4a7c15)
const passes = 3

type spoonge struct {
	v0, v1, v2, v3 uint64
}

func permuteRight(s *spoonge) {
	v0, v1, v2, v3 := s.v0, s.v1, s.v2, s.v3
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
	v2 = bits.RotateLeft64(v2, 32)
	s.v0, s.v1, s.v2, s.v3 = v0, v1, v2, v3
}

func permuteLeft(s *spoonge) {
	v0, v1, v2, v3 := s.v0, s.v1, s.v2, s.v3
	v2 = bits.RotateLeft64(v2, 32)
	v1 ^= v2
	v3 ^= v0
	v1 = bits.RotateLeft64(v1, 64-17)
	v3 = bits.RotateLeft64(v3, 64-21)
	v2 -= v1
	v0 -= v3
	v0 = bits.RotateLeft64(v0, 32)
	v1 ^= v0
	v3 ^= v2
	v1 = bits.RotateLeft64(v1, 64-13)
	v3 = bits.RotateLeft64(v3, 64-16)
	v0 -= v1
	v2 -= v3
	s.v0, s.v1, s.v2, s.v3 = v0, v1, v2, v3
}

func Seal(key, nonce, plaintext []byte) (ciphertext []byte) {
	k1, k2 := bytesTo2U64(key)
	n1, n2 := bytesTo2U64(nonce)
	p64 := bytesToU64s(plaintext, true)

	state := spoonge{
		v0: k1 ^ 0x736f6d6570736575,
		v1: k2 ^ 0x646f72616e646f6d,
		v2: k1 ^ 0x6c7967656e657261,
		v3: k2 ^ 0x7465646279746573,
	}

	state.v3 ^= n1
	permuteRight(&state)
	state.v3 ^= n2
	permuteRight(&state)

	state.v0 ^= 0xfd

	lp64 := len(p64) - 4
	pp := p64[:lp64]
	gamma := uint64(0)
	v0, v1, v2, v3 := state.v0, state.v1, state.v2, state.v3
	for n := 0; n < passes; n++ {
		for i, p := range pp {
			v3 ^= p
			v1 ^= bits.RotateLeft64(k1, int(gamma>>58))
			v2 ^= n1 + gamma
			{
				v0 += v1
				v2 += v3
				v1 = bits.RotateLeft64(v1, 13)
				v3 = bits.RotateLeft64(v3, 16)
				v1 ^= v0
				v3 ^= v2
				v2 = bits.RotateLeft64(v2, 32)
				v2 += v1
				v0 += v3
				v1 = bits.RotateLeft64(v1, 17)
				v3 = bits.RotateLeft64(v3, 21)
				v1 ^= v2
				v3 ^= v0
				v0 = bits.RotateLeft64(v0, 32)
			}
			v0 ^= p
			pp[i] += v3
			gamma += delta
			k1, k2 = k2, k1
			n1, n2 = n2, n1
		}
	}
	state.v0, state.v1, state.v2, state.v3 = v0, v1, v2, v3

	state.v1 ^= k1
	state.v3 ^= k2
	state.v0 ^= n2 + 0xfe
	state.v2 ^= n1 + gamma
	for n := 0; n < 4; n++ {
		permuteRight(&state)
	}
	state.v1 ^= k1 + k2
	state.v3 ^= k2 + 2*k1
	state.v0 ^= n2
	state.v2 ^= n1
	p64[lp64] = state.v0
	p64[lp64+1] = state.v1
	p64[lp64+2] = state.v2
	p64[lp64+3] = state.v3
	res := u64sToBytes(p64)
	return res
}

func Open(key, nonce, ciphertext []byte) (plaintext []byte) {
	k1, k2 := bytesTo2U64(key)
	n1, n2 := bytesTo2U64(nonce)
	p64 := bytesToU64s(ciphertext, false)
	lp64 := len(p64) - 4
	pp := p64[:lp64]

	nix := lp64 * passes
	if nix&1 != 0 {
		n1, n2 = n2, n1
		k1, k2 = k2, k1
	}
	gamma := delta * uint64(nix)

	state := spoonge{
		v0: p64[lp64],
		v1: p64[lp64+1],
		v2: p64[lp64+2],
		v3: p64[lp64+3],
	}
	state.v1 ^= k1 + k2
	state.v3 ^= k2 + 2*k1
	state.v0 ^= n2
	state.v2 ^= n1
	for n := 0; n < 4; n++ {
		permuteLeft(&state)
	}
	state.v1 ^= k1
	state.v3 ^= k2
	state.v0 ^= n2 + 0xfe
	state.v2 ^= n1 + gamma

	v0, v1, v2, v3 := state.v0, state.v1, state.v2, state.v3
	for n := 0; n < passes; n++ {
		for i := len(pp) - 1; i >= 0; i-- {
			gamma -= delta
			k1, k2 = k2, k1
			n1, n2 = n2, n1

			pp[i] -= v3
			v0 ^= pp[i]
			{
				v0 = bits.RotateLeft64(v0, 32)
				v1 ^= v2
				v3 ^= v0
				v1 = bits.RotateLeft64(v1, 64-17)
				v3 = bits.RotateLeft64(v3, 64-21)
				v2 -= v1
				v0 -= v3
				v2 = bits.RotateLeft64(v2, 32)
				v1 ^= v0
				v3 ^= v2
				v1 = bits.RotateLeft64(v1, 64-13)
				v3 = bits.RotateLeft64(v3, 64-16)
				v0 -= v1
				v2 -= v3
			}
			v1 ^= bits.RotateLeft64(k1, int(gamma>>58))
			v2 ^= n1 + gamma
			v3 ^= pp[i]
		}
	}

	state.v0, state.v1, state.v2, state.v3 = v0, v1, v2, v3

	state.v0 ^= 0xfd

	permuteLeft(&state)
	state.v3 ^= n2
	permuteLeft(&state)
	state.v3 ^= n1

	compare := spoonge{
		v0: k1 ^ 0x736f6d6570736575,
		v1: k2 ^ 0x646f72616e646f6d,
		v2: k1 ^ 0x6c7967656e657261,
		v3: k2 ^ 0x7465646279746573,
	}
	if state != compare {
		panic("NO KEY")
	}

	buf := u64sToBytes(pp)
	padlen := int(buf[len(buf)-1])
	if padlen > len(buf) {
		panic("NO LEN")
	}
	sum := uint32(0)
	for _, x := range buf[len(buf)-padlen : len(buf)-1] {
		sum |= uint32(x)
	}
	if sum != 0 {
		panic("NO PAD")
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

func bytesToU64s(b []byte, encode bool) (res []uint64) {
	sz := len(b)
	if encode {
		sz = (sz + 1 + 7) &^ 7
		if sz < 24 {
			sz = 24
		}
		sz += 32
	}
	br := make([]byte, sz)
	copy(br, b)
	if encode {
		br[sz-33] = byte(sz - 32 - len(b))
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
