package escrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func deriveKEK(passcode, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(passcode, salt, iterations, keyLen, sha256.New)
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("escrow: iv length %d != block size %d", len(iv), block.BlockSize())
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("escrow: ciphertext not a multiple of block size (%d)", len(ciphertext))
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}
