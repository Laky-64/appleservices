package ckks

import "fmt"

const KeyLen = 64

func UnwrapKey(wrappingKey, wrapped []byte) ([]byte, error) {
	if len(wrappingKey) != KeyLen {
		return nil, fmt.Errorf("ckks: wrapping key length %d, want %d", len(wrappingKey), KeyLen)
	}
	key, err := SIVDecrypt(wrappingKey, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("ckks: unwrap key: %w", err)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("ckks: unwrapped key length %d, want %d", len(key), KeyLen)
	}
	return key, nil
}

func WrapKey(wrappingKey, key []byte) ([]byte, error) {
	if len(wrappingKey) != KeyLen {
		return nil, fmt.Errorf("ckks: wrapping key length %d, want %d", len(wrappingKey), KeyLen)
	}
	if len(key) != KeyLen {
		return nil, fmt.Errorf("ckks: key length %d, want %d", len(key), KeyLen)
	}
	return SIVEncrypt(wrappingKey, key, nil)
}
