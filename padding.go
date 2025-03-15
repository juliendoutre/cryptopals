package cryptopals

import "fmt"

type Padding interface {
	Pad(text []byte) []byte
	Unpad(text []byte) ([]byte, error)
}

type PKCS7 struct {
	Length byte
}

func (p PKCS7) Pad(text []byte) []byte {
	if p.Length == 0 {
		return text
	}

	remainder := len(text) % int(p.Length)

	suffixLength := int(p.Length) - remainder

	paddedText := text

	for range suffixLength {
		paddedText = append(paddedText, byte(suffixLength))
	}

	return paddedText
}

func (p PKCS7) Unpad(text []byte) ([]byte, error) {
	if p.Length == 0 || len(text) == 0 {
		return text, nil
	}

	if len(text)%int(p.Length) != 0 {
		return nil, fmt.Errorf("invalid padded text length")
	}

	paddingByte := text[len(text)-1]

	for i := 1; i <= int(paddingByte); i++ {
		if text[len(text)-i] != paddingByte {
			return nil, fmt.Errorf("invalid padding sequence")
		}
	}

	return text[:len(text)-int(paddingByte)], nil
}

var _ Padding = PKCS7{}
