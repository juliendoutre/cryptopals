package cryptopals

import (
	"unicode"
)

func EnglishScore(input []byte) float64 {
	score := .0

	for _, c := range string(input) {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || unicode.IsSpace(c) {
			score++
		}
	}

	// Normalize the score
	return score / float64(len(input))
}
