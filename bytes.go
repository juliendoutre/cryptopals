package cryptopals

import (
	"crypto/rand"
	"math/big"
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

func Random128Bits() [16]byte {
	key := [16]byte{}
	_, _ = rand.Read(key[:])

	return key
}

func RandomBool() bool {
	buffer := make([]byte, 1)
	n, _ := rand.Read(buffer)

	return n%2 == 0
}

func RandomInt(minimum, maximum int64) int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(maximum-minimum))

	return n.Int64() + minimum
}

func RandomBytes(minimum, maximum int64) []byte {
	length := RandomInt(minimum, maximum)
	bytes := make([]byte, length)
	_, _ = rand.Read(bytes)

	return bytes
}
