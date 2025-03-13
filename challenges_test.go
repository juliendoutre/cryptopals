package cryptopals_test

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/juliendoutre/cryptopals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed data/4.txt
var data4 string

//go:embed data/6.txt
var data6 string

//go:embed data/7.txt
var data7 string

//go:embed data/8.txt
var data8 string

// https://cryptopals.com/sets/1
func TestSet1(t *testing.T) {
	t.Parallel()

	// https://cryptopals.com/sets/1/challenges/1
	t.Run("challenge 1", func(t *testing.T) {
		t.Parallel()

		raw, err := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
		require.NoError(t, err)

		assert.Equal(t, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", base64.StdEncoding.EncodeToString(raw))
	})

	// https://cryptopals.com/sets/1/challenges/2
	t.Run("challenge 2", func(t *testing.T) {
		t.Parallel()

		a, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
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

		_, plaintext, isCracked := cryptopals.SingleByteXor{}.Crack(ciphertext)
		assert.True(t, isCracked)
		assert.Equal(t, "Cooking MC's like a pound of bacon", string(plaintext))
	})

	// https://cryptopals.com/sets/1/challenges/4
	t.Run("challenge 4", func(t *testing.T) {
		t.Parallel()

		scanner := bufio.NewScanner(bytes.NewBufferString(data4))

		for scanner.Scan() {
			ciphertext, err := hex.DecodeString(scanner.Text())
			require.NoError(t, err)

			_, plaintext, isCracked := cryptopals.SingleByteXor{}.Crack(ciphertext)
			if isCracked {
				assert.Equal(t, "Now that the party is jumping\n", string(plaintext))
			}
		}

		assert.NoError(t, scanner.Err())
	})

	// https://cryptopals.com/sets/1/challenges/5
	t.Run("challenge 5", func(t *testing.T) {
		t.Parallel()

		plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

		cipher := cryptopals.RepeatingKeyXor{Key: []byte("ICE")}
		ciphertext := hex.EncodeToString(cipher.Encrypt([]byte(plaintext)))
		assert.Equal(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", ciphertext)
	})

	// https://cryptopals.com/sets/1/challenges/6
	t.Run("challenge 6", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, 37, cryptopals.HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!")))

		ciphertext, err := base64.StdEncoding.DecodeString(data6)
		require.NoError(t, err)

		for keySize := range 40 {
			_, _, _ = cryptopals.RepeatingKeyXor{}.Crack(ciphertext, keySize)
		}
	})

	// https://cryptopals.com/sets/1/challenges/7
	t.Run("challenge 7", func(t *testing.T) {
		t.Parallel()

		ciphertext, err := base64.StdEncoding.DecodeString(data7)
		require.NoError(t, err)

		plaintext := cryptopals.AES128ECB{Key: [16]byte([]byte("YELLOW SUBMARINE"))}.Decrypt(ciphertext)

		t.Log(string(plaintext))
	})

	// https://cryptopals.com/sets/1/challenges/8
	t.Run("challenge 8", func(t *testing.T) {
		t.Parallel()

		keySize := 2 * 16

		maximumDuplicateBlocksCount := 0
		lineIndexWithTheMostDuplicates := 0

		for lineIndex, line := range strings.Split(data8, "\n") {
			if line == "" {
				continue
			}

			blocks := make(map[string]int, 0)

			for i := range len(line) / keySize {
				if _, ok := blocks[line[i*keySize:(i+1)*keySize]]; !ok {
					blocks[line[i*keySize:(i+1)*keySize]] = 1
				} else {
					blocks[line[i*keySize:(i+1)*keySize]]++
				}
			}

			maximumLineDuplicateBlocksCount := 0
			for _, count := range blocks {
				if count > maximumLineDuplicateBlocksCount {
					maximumLineDuplicateBlocksCount = count
				}
			}

			if maximumLineDuplicateBlocksCount > maximumDuplicateBlocksCount {
				maximumDuplicateBlocksCount = maximumLineDuplicateBlocksCount
				lineIndexWithTheMostDuplicates = lineIndex
			}
		}

		assert.Equal(t, 132, lineIndexWithTheMostDuplicates)
		assert.Equal(t, 4, maximumDuplicateBlocksCount)
	})
}

// https://cryptopals.com/sets/2
func TestSet2(t *testing.T) {
	t.Parallel()

	// https://cryptopals.com/sets/2/challenges/9
	t.Run("challenge 9", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), cryptopals.PKCS7{Length: 20}.Pad([]byte("YELLOW SUBMARINE")))
	})
}
