package cryptopals

import "bytes"

type Oracle struct{}

func (o Oracle) IsECB(cipher Cipher) bool {
	plaintext := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	plaintext = append(RandomBytes(5, 11), plaintext...)
	plaintext = append(plaintext, RandomBytes(5, 11)...)
	ciphertext := cipher.Encrypt(plaintext)
	return bytes.Equal(ciphertext[16:32], ciphertext[32:48])
}
