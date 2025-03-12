package cryptopals

type Padding interface {
	Pad(text []byte) []byte
	Unpad(text []byte) []byte
}

type PKCS7 struct {
	Length int
}

func (p PKCS7) Pad(text []byte) []byte {
	remainder := len(text) % p.Length

	if remainder == 0 {
		return text
	}

	suffixLength := p.Length - remainder

	paddedText := text

	for range suffixLength {
		paddedText = append(paddedText, byte(suffixLength))
	}

	return paddedText
}

func (p PKCS7) Unpad(text []byte) []byte {
	index := len(text)

	// TODO

	return text[:index]
}

var _ Padding = PKCS7{}
