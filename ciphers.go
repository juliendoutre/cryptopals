package cryptopals

import (
	"crypto/aes"
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

var _ Cipher = SingleByteXor{}

func CrackSingleByteXor(ciphertext []byte) SingleByteXor {
	bestCandidate, bestScore := 0, 0.

	for candidate := range 256 {
		score := EnglishScore(SingleByteXor{Key: byte(candidate)}.Decrypt(ciphertext))
		if score > bestScore {
			bestCandidate = candidate
			bestScore = score
		}
	}

	return SingleByteXor{Key: byte(bestCandidate)}
}

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

func CrackRepeatingKeyXor(ciphertext []byte) RepeatingKeyXor {
	keySize := guessKeySize(2, 40, ciphertext)

	key := make([]byte, keySize)

	for i := range keySize {
		keyByte := CrackSingleByteXor(transposeBlock(ciphertext, keySize, i)).Key
		key[i] = keyByte
	}

	return RepeatingKeyXor{Key: key}
}

func transposeBlock(ciphertext []byte, blockSize, index int) []byte {
	if blockSize == 0 {
		return []byte{}
	}

	N := len(ciphertext) / blockSize

	block := make([]byte, N)

	for j := range N {
		block[j] = ciphertext[blockSize*j+index]
	}

	if N*blockSize+index < len(ciphertext) {
		block = append(block, ciphertext[N*blockSize+index]) //nolint:makezero
	}

	return block
}

func guessKeySize(minKeySize, maxKeySize int, ciphertext []byte) int {
	guess := minKeySize
	guessDistance := 8.

	for keySize := minKeySize; keySize < maxKeySize; keySize++ {
		distance := 0.

		for i := 1; i < len(ciphertext)/keySize-1; i++ {
			distance += float64(HammingDistance(ciphertext[:keySize], ciphertext[i*keySize:(i+1)*keySize]))
		}

		distance /= (float64(len(ciphertext)/keySize-2) * float64(keySize))

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
