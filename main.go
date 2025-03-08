package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"unicode"
)

func HexToBase64(input string) (string, error) {
	raw, err := hex.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("decoding hex string: %w", err)
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

func Xor(a, b []byte) []byte {
	out := make([]byte, len(a))

	for i := range a {
		out[i] = a[i] ^ b[i]
	}

	return out
}

func Block(a byte, length int) []byte {
	out := make([]byte, length)

	for i := range out {
		out[i] = a
	}

	return out
}

func IsEnglish(input string) bool {
	for _, c := range input {
		if !(unicode.IsLetter(c) || unicode.IsSpace(c) || unicode.IsDigit(c) || c == '\'') {
			return false
		}
	}

	return true
}

func CrackSingleCharXor(ciphertext []byte) (byte, string, bool) {
	for candidate := range math.MaxUint8 {
		plaintext := string(Xor(ciphertext, Block(byte(candidate), len(ciphertext))))

		if IsEnglish(plaintext) {
			return byte(candidate), plaintext, true
		}
	}

	return 0, "", false
}

func RepeatingKeyXor(plaintext, key []byte) []byte {
	ciphertext := make([]byte, len(plaintext))

	for index := range plaintext {
		ciphertext[index] = plaintext[index] ^ key[index%len(key)]
	}

	return ciphertext
}
