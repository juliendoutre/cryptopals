package cryptopals_test

import (
	"encoding/base64"
	"testing"

	"github.com/juliendoutre/cryptopals"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// https://cryptopals.com/sets/2
func TestSet2(t *testing.T) {
	t.Parallel()

	// https://cryptopals.com/sets/2/challenges/9
	t.Run("challenge 9", func(t *testing.T) {
		t.Parallel()

		padding := cryptopals.PKCS7{Length: 20}
		assert.Equal(t, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), padding.Pad([]byte("YELLOW SUBMARINE")))
	})

	// https://cryptopals.com/sets/2/challenges/10
	t.Run("challenge 10", func(t *testing.T) {
		t.Parallel()

		ciphertext, err := base64.StdEncoding.DecodeString(data10)
		require.NoError(t, err)

		cipher := cryptopals.AES128CBC{
			Key: [16]byte([]byte("YELLOW SUBMARINE")),
			IV:  [16]byte{},
		}

		t.Log(string(cipher.Decrypt(ciphertext)))
	})

	t.Run("challenge 15", func(t *testing.T) {
		t.Parallel()

		padding := cryptopals.PKCS7{Length: 20}

		unpaddedText, err := padding.Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04"))
		assert.NoError(t, err)
		assert.Equal(t, "ICE ICE BABY", string(unpaddedText))

		_, err = padding.Unpad([]byte("ICE ICE BABY\x05\x05\x05\x05"))
		assert.Error(t, err)

		_, err = padding.Unpad([]byte("ICE ICE BABY\x01\x02\x03\x04"))
		assert.Error(t, err)
	})
}
