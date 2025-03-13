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
	ciphertext := make([]byte, len(plaintext))

	for index := range plaintext {
		ciphertext[index] = plaintext[index] ^ s.Key
	}

	return ciphertext
}

func (s SingleByteXor) Decrypt(ciphertext []byte) []byte {
	return s.Encrypt(ciphertext)
}

func (s SingleByteXor) Crack(ciphertext []byte) (byte, []byte, bool) {
	for candidate := range math.MaxUint8 {
		s.Key = byte(candidate)

		plaintext := s.Decrypt(ciphertext)

		if IsEnglish(plaintext) {
			return s.Key, plaintext, true
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

func (r RepeatingKeyXor) Crack(ciphertext []byte, keySize int) ([]byte, []byte, bool) {
	key := make([]byte, keySize)

	for i := range keySize {
		keyByte, _, isCracked := SingleByteXor{}.Crack(transposeBlock(ciphertext, keySize, i))
		if !isCracked {
			return nil, nil, false
		}

		key[i] = keyByte
	}

	// TODO: return plaintext

	return key, nil, true
}

func transposeBlock(ciphertext []byte, blockSize, index int) []byte {
	block := make([]byte, len(ciphertext)/blockSize)

	for j := range len(ciphertext) / blockSize {
		block[j] = ciphertext[blockSize*j+index]
	}

	// TODO: add final block

	return block
}

func (r RepeatingKeyXor) guessKeySize(minKeySize, maxKeySize int, ciphertext []byte) int {
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
