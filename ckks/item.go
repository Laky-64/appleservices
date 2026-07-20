package ckks

import (
	"crypto/rand"
	"fmt"
)

const itemNonceLen = 16

func EncryptItem(itemKey, plaintext []byte, ad [][]byte) ([]byte, error) {
	if len(itemKey) != KeyLen {
		return nil, fmt.Errorf("ckks: item key length %d, want %d", len(itemKey), KeyLen)
	}
	nonce := make([]byte, itemNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ckks: nonce: %w", err)
	}
	sealed, err := SIVEncrypt(itemKey, plaintext, prependNonce(nonce, ad))
	if err != nil {
		return nil, fmt.Errorf("ckks: encrypt item: %w", err)
	}
	return append(nonce, sealed...), nil
}

func DecryptItem(itemKey, data []byte, ad [][]byte) ([]byte, error) {
	if len(itemKey) != KeyLen {
		return nil, fmt.Errorf("ckks: item key length %d, want %d", len(itemKey), KeyLen)
	}
	if len(data) < itemNonceLen+blockSize {
		return nil, fmt.Errorf("ckks: item data too short: %d", len(data))
	}
	nonce := data[:itemNonceLen]
	plaintext, err := SIVDecrypt(itemKey, data[itemNonceLen:], prependNonce(nonce, ad))
	if err != nil {
		return nil, fmt.Errorf("ckks: decrypt item: %w", err)
	}
	return plaintext, nil
}

func prependNonce(nonce []byte, ad [][]byte) [][]byte {
	out := make([][]byte, 0, len(ad)+1)
	out = append(out, nonce)
	out = append(out, ad...)
	return out
}
