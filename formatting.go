package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"unicode"
)

func HexToBase64(input string) (string, error) {
	raw, err := hex.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("decoding hex string: %w", err)
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

func IsEnglish(input []byte) bool {
	for _, c := range string(input) {
		if !(unicode.IsLetter(c) || unicode.IsSpace(c) || unicode.IsDigit(c) || c == '\'') {
			return false
		}
	}

	return true
}
