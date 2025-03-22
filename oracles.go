package cryptopals

import "bytes"

func IsECB(cipher Cipher, blockSize int) bool {
	plaintext := SingleCharBlock('A', blockSize*3)
	ciphertext := cipher.Encrypt(plaintext)

	return bytes.Equal(ciphertext[blockSize:2*blockSize], ciphertext[2*blockSize:3*blockSize])
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
