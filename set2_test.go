package cryptopals_test

import (
	"bytes"
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

	// https://cryptopals.com/sets/2/challenges/11
	t.Run("challenge 11", func(t *testing.T) {
		t.Parallel()

		for range 100 {
			key := cryptopals.Random128Bits()
			cipher, isECB := randomCipher(key)

			plaintext := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			plaintext = append(cryptopals.RandomBytes(5, 11), plaintext...)
			plaintext = append(plaintext, cryptopals.RandomBytes(5, 11)...)

			ciphertext := cipher.Encrypt(plaintext)

			assert.Equal(t, isECB, bytes.Equal(ciphertext[16:32], ciphertext[32:48]))
		}
	})

	// https://cryptopals.com/sets/2/challenges/12
	t.Run("challenge 12", func(t *testing.T) {
		t.Parallel()
	})

	// https://cryptopals.com/sets/2/challenges/15
	t.Run("challenge 15", func(t *testing.T) {
		t.Parallel()

		padding := cryptopals.PKCS7{Length: 16}

		unpaddedText, err := padding.Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04"))
		require.NoError(t, err)
		assert.Equal(t, "ICE ICE BABY", string(unpaddedText))

		_, err = padding.Unpad([]byte("ICE ICE BABY\x05\x05\x05\x05"))
		require.Error(t, err)

		_, err = padding.Unpad([]byte("ICE ICE BABY\x01\x02\x03\x04"))
		require.Error(t, err)
	})
}

//nolint:ireturn
func randomCipher(key [16]byte) (cryptopals.Cipher, bool) {
	if cryptopals.RandomBool() {
		return cryptopals.AES128ECB{Key: key}, true
	}

	return cryptopals.AES128CBC{
		Key: key,
		IV:  cryptopals.Random128Bits(),
	}, false
}
