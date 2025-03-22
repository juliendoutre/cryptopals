package cryptopals

import "bytes"

func IsECB(cipher Cipher) bool {
	plaintext := SingleCharBlock('A', 16*3)
	ciphertext := cipher.Encrypt(plaintext)

	return bytes.Equal(ciphertext[16:32], ciphertext[32:48])
}

func GuessBlockSize(cipher Cipher) int {
	candidate := 1

	initialCiphertextLength := len(cipher.Encrypt(SingleCharBlock('A', candidate)))

	for {
		candidate++
		ciphertext := cipher.Encrypt(SingleCharBlock('A', candidate))

		if len(ciphertext) > initialCiphertextLength {
			return len(ciphertext) - initialCiphertextLength
		}
	}
}
