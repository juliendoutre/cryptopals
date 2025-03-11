package cryptopals

import "math"

var SingleByteXor = singleByteXor{}

type singleByteXor struct{}

func (s singleByteXor) Encrypt(plaintext []byte, key byte) []byte {
	return Xor(plaintext, NewSingleByteBlock(key, len(plaintext)))
}

func (s singleByteXor) Decrypt(ciphertext []byte, key byte) []byte {
	return s.Encrypt(ciphertext, key)
}

func (s singleByteXor) Crack(ciphertext []byte) (byte, []byte, bool) {
	for candidate := range math.MaxUint8 {
		plaintext := Xor(ciphertext, NewSingleByteBlock(byte(candidate), len(ciphertext)))

		if IsEnglish(plaintext) {
			return byte(candidate), plaintext, true
		}
	}

	return 0, nil, false
}

var RepeatingKeyXor = repeatingKeyXor{}

type repeatingKeyXor struct{}

func (r repeatingKeyXor) Encrypt(plaintext []byte, key []byte) []byte {
	ciphertext := make([]byte, len(plaintext))

	for index := range plaintext {
		ciphertext[index] = plaintext[index] ^ key[index%len(key)]
	}

	return ciphertext
}

func (r repeatingKeyXor) Decrypt(ciphertext []byte, key []byte) []byte {
	return r.Encrypt(ciphertext, key)
}

func (r repeatingKeyXor) Crack(ciphertext []byte) []byte {
	keySize := r.GuessKeySize(2, 41, ciphertext)

	transposedBlocks := make([][]byte, keySize)

	for blockIndex := range keySize {
		transposedBlocks[blockIndex] = []byte{}
		for keyIndex := range len(ciphertext) / keySize {
			index := blockIndex*keySize + keyIndex

			transposedBlocks[blockIndex] = append(transposedBlocks[blockIndex], ciphertext[index])
		}
	}

	return nil
}

func (r repeatingKeyXor) GuessKeySize(min, max int, ciphertext []byte) int {
	guess := min
	guessDistance := float64(8)

	for keySize := min; keySize < max; keySize++ {
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
