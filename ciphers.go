package cryptopals

import (
	"crypto/aes"
	"math"
)

type Cipher interface {
	Encrypt(plaintext []byte) []byte
	Decrypt(ciphertext []byte) []byte
}

type SingleByteXor struct {
	Key byte
}

func (s SingleByteXor) Encrypt(plaintext []byte) []byte {
	return Xor(plaintext, NewSingleByteBlock(s.Key, len(plaintext)))
}

func (s SingleByteXor) Decrypt(ciphertext []byte) []byte {
	return s.Encrypt(ciphertext)
}

func (s SingleByteXor) Crack(ciphertext []byte) (byte, []byte, bool) {
	for candidate := range math.MaxUint8 {
		plaintext := Xor(ciphertext, NewSingleByteBlock(byte(candidate), len(ciphertext)))

		if IsEnglish(plaintext) {
			return byte(candidate), plaintext, true
		}
	}

	return 0, nil, false
}

var _ Cipher = SingleByteXor{}

type RepeatingKeyXor struct {
	Key []byte
}

func (r RepeatingKeyXor) Encrypt(plaintext []byte) []byte {
	if len(r.Key) == 0 {
		return plaintext
	}

	ciphertext := make([]byte, len(plaintext))

	for index := range plaintext {
		ciphertext[index] = plaintext[index] ^ r.Key[index%len(r.Key)]
	}

	return ciphertext
}

func (r RepeatingKeyXor) Decrypt(ciphertext []byte) []byte {
	return r.Encrypt(ciphertext)
}

var _ Cipher = RepeatingKeyXor{}

func (r RepeatingKeyXor) Crack(ciphertext []byte) ([]byte, []byte, bool) {
	keySize := r.GuessKeySize(2, 41, ciphertext)

	transposedBlocks := make([][]byte, keySize)

	for blockIndex := range keySize {
		transposedBlocks[blockIndex] = []byte{}

		for keyIndex := range len(ciphertext) / keySize {
			index := blockIndex*keySize + keyIndex

			transposedBlocks[blockIndex] = append(transposedBlocks[blockIndex], ciphertext[index])
		}
	}

	return nil, nil, false
}

func (r RepeatingKeyXor) GuessKeySize(minKeySize, maxKeySize int, ciphertext []byte) int {
	guess := minKeySize
	guessDistance := float64(8)

	for keySize := minKeySize; keySize < maxKeySize; keySize++ {
		block1 := ciphertext[0:keySize]
		block2 := ciphertext[keySize : 2*keySize]
		block3 := ciphertext[2*keySize : 3*keySize]
		block4 := ciphertext[3*keySize : 4*keySize]

		distance := float64(HammingDistance(block1, block2) + HammingDistance(block1, block3) + HammingDistance(block1, block4))
		distance /= 3 * float64(keySize)

		if distance < guessDistance {
			guess = keySize
			guessDistance = distance
		}
	}

	return guess
}

type AES128ECB struct {
	Key [16]byte
}

func (a AES128ECB) Encrypt(plaintext []byte) []byte {
	cipher, _ := aes.NewCipher(a.Key[:])

	ciphertext := make([]byte, len(plaintext))

	for i := range len(plaintext) / len(a.Key) {
		cipher.Encrypt(ciphertext[i*len(a.Key):(i+1)*len(a.Key)], plaintext[i*len(a.Key):(i+1)*len(a.Key)])
	}

	return ciphertext
}

func (a AES128ECB) Decrypt(ciphertext []byte) []byte {
	cipher, _ := aes.NewCipher(a.Key[:])

	plaintext := make([]byte, len(ciphertext))

	for i := range len(ciphertext) / len(a.Key) {
		cipher.Decrypt(plaintext[i*len(a.Key):(i+1)*len(a.Key)], ciphertext[i*len(a.Key):(i+1)*len(a.Key)])
	}

	return plaintext
}

var _ Cipher = AES128ECB{}

type AESCBC struct {
	Key []byte
	IV  []byte
}

func (a AESCBC) Encrypt(plaintext []byte) []byte {
	return nil
}

func (a AESCBC) Decrypt(plaintext []byte) []byte {
	return nil
}

var _ Cipher = AESCBC{}
