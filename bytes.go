package cryptopals

import (
	"crypto/rand"
	"math/bits"
)

func Xor(a, b []byte) []byte {
	out := make([]byte, len(a))

	for i := range a {
		out[i] = a[i] ^ b[i]
	}

	return out
}

func HammingDistance(a, b []byte) int {
	count := 0

	for index := range a {
		count += bits.OnesCount8(a[index] ^ b[index])
	}

	return count
}

func Random128BitsKey() [16]byte {
	key := [16]byte{}
	rand.Read(key[:]) //nolint:errcheck

	return key
}
