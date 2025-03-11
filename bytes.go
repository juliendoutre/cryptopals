package cryptopals

import "math/bits"

func Xor(a, b []byte) []byte {
	out := make([]byte, len(a))

	for i := range a {
		out[i] = a[i] ^ b[i]
	}

	return out
}

func NewSingleByteBlock(a byte, length int) []byte {
	out := make([]byte, length)

	for i := range out {
		out[i] = a
	}

	return out
}

func HammingDistance(a, b []byte) int {
	count := 0

	for index := range len(a) {
		count += bits.OnesCount8(a[index] ^ b[index])
	}

	return count
}
