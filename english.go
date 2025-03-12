package cryptopals

import (
	"unicode"
)

func IsEnglish(input []byte) bool {
	for _, c := range string(input) {
		if !(unicode.IsLetter(c) || unicode.IsSpace(c) || unicode.IsDigit(c) || c == '\'') {
			return false
		}
	}

	return true
}
