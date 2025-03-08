package cryptopals_test

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/hex"
	"testing"

	"github.com/juliendoutre/cryptopals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed data/4.txt
var data string

// https://cryptopals.com/sets/1
func TestSet1(t *testing.T) {
	t.Parallel()

	// https://cryptopals.com/sets/1/challenges/1
	t.Run("challenge 1", func(t *testing.T) {
		t.Parallel()

		actual, err := cryptopals.HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") //nolint:lll
		require.NoError(t, err)

		assert.Equal(t, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", actual)
	})

	// https://cryptopals.com/sets/1/challenges/2
	t.Run("challenge 2", func(t *testing.T) {
		t.Parallel()

		a, err := hex.DecodeString("1c0111001f010100061a024b53535009181c") //nolint:varnamelen
		require.NoError(t, err)

		b, err := hex.DecodeString("686974207468652062756c6c277320657965")
		require.NoError(t, err)

		assert.Equal(t, "746865206b696420646f6e277420706c6179", hex.EncodeToString(cryptopals.Xor(a, b)))
	})

	// https://cryptopals.com/sets/1/challenges/3
	t.Run("challenge 3", func(t *testing.T) {
		t.Parallel()

		ciphertext, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
		require.NoError(t, err)

		_, plaintext, isCracked := cryptopals.CrackSingleCharXor(ciphertext)
		assert.True(t, isCracked)
		assert.Equal(t, "Cooking MC's like a pound of bacon", plaintext)
	})

	// https://cryptopals.com/sets/1/challenges/4
	t.Run("challenge 4", func(t *testing.T) {
		t.Parallel()

		scanner := bufio.NewScanner(bytes.NewBufferString(data))

		for scanner.Scan() {
			ciphertext, err := hex.DecodeString(scanner.Text())
			require.NoError(t, err)

			_, plaintext, isCracked := cryptopals.CrackSingleCharXor(ciphertext)
			if isCracked {
				assert.Equal(t, "Now that the party is jumping\n", plaintext)
			}
		}

		assert.NoError(t, scanner.Err())
	})
}
