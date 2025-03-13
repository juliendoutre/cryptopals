package cryptopals

type Padding interface {
	Pad(text []byte) []byte
	Unpad(text []byte) []byte
}

type PKCS7 struct {
	Length byte
}

func (p PKCS7) Pad(text []byte) []byte {
	if p.Length == 0 {
		return text
	}

	remainder := len(text) % int(p.Length)

	if remainder == 0 {
		return text
	}

	suffixLength := int(p.Length) - remainder

	paddedText := text

	for range suffixLength {
		paddedText = append(paddedText, byte(suffixLength))
	}

	return paddedText
}

func (p PKCS7) Unpad(text []byte) []byte {
	if p.Length == 0 {
		return text
	}

	if len(text) < int(p.Length) {
		return text
	}

	paddingByte := text[len(text)-1]

	for i := 1; i < int(paddingByte); i++ {
		if text[len(text)-i] != paddingByte {
			return text
		}
	}

	return text[:len(text)-int(paddingByte)]
}

var _ Padding = PKCS7{}
