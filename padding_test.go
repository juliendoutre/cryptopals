package cryptopals_test

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/juliendoutre/cryptopals"
)

func TestPKCS7(t *testing.T) {
	t.Parallel()

	f := func(length byte, text []byte) bool {
		padding := cryptopals.PKCS7{Length: length}

		return bytes.Equal(text, padding.Unpad(padding.Pad(text)))
	}

	if err := quick.Check(f, &quick.Config{}); err != nil {
		t.Error(err)
	}
}
