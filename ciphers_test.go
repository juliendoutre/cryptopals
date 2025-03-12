package cryptopals_test

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/juliendoutre/cryptopals"
)

func TestSingleByteXor(t *testing.T) {
	t.Parallel()

	f := func(plaintext []byte, key byte) bool {
		cipher := cryptopals.SingleByteXor{Key: key}

		return bytes.Equal(plaintext, cipher.Decrypt(cipher.Encrypt(plaintext)))
	}

	if err := quick.Check(f, &quick.Config{}); err != nil {
		t.Error(err)
	}
}

func TestRepeatingKeyXor(t *testing.T) {
	t.Parallel()

	f := func(plaintext, key []byte) bool {
		cipher := cryptopals.RepeatingKeyXor{Key: key}

		return bytes.Equal(plaintext, cipher.Decrypt(cipher.Encrypt(plaintext)))
	}

	if err := quick.Check(f, &quick.Config{}); err != nil {
		t.Error(err)
	}
}

func TestAES128ECB(t *testing.T) {
	t.Parallel()

	padding := cryptopals.PKCS7{Length: 16}

	f := func(plaintext []byte, key [16]byte) bool {
		cipher := cryptopals.AES128ECB{Key: key}

		return bytes.Equal(plaintext, padding.Unpad(cipher.Decrypt(cipher.Encrypt(padding.Pad(plaintext)))))
	}

	if err := quick.Check(f, &quick.Config{}); err != nil {
		t.Error(err)
	}
}
