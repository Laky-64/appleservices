package ckks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

const blockSize = 16

func dbl(b []byte) []byte {
	out := make([]byte, len(b))
	var carry byte
	for i := len(b) - 1; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	if b[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func xor(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func pad(b []byte) []byte {
	out := make([]byte, blockSize)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

func encBlock(block cipher.Block, in []byte) []byte {
	out := make([]byte, blockSize)
	block.Encrypt(out, in)
	return out
}

func cmac(block cipher.Block, msg []byte) []byte {
	l := encBlock(block, make([]byte, blockSize))
	k1 := dbl(l)
	k2 := dbl(k1)

	n := (len(msg) + blockSize - 1) / blockSize
	complete := len(msg) > 0 && len(msg)%blockSize == 0
	if n == 0 {
		n = 1
	}

	var last []byte
	lastBlock := msg[(n-1)*blockSize:]
	if complete {
		last = xor(lastBlock, k1)
	} else {
		last = xor(pad(lastBlock), k2)
	}

	x := make([]byte, blockSize)
	for i := 0; i < n-1; i++ {
		x = encBlock(block, xor(x, msg[i*blockSize:(i+1)*blockSize]))
	}
	return encBlock(block, xor(x, last))
}

func xorend(s, d []byte) []byte {
	out := make([]byte, len(s))
	copy(out, s)
	off := len(s) - len(d)
	for i := 0; i < len(d); i++ {
		out[off+i] ^= d[i]
	}
	return out
}

func s2v(block cipher.Block, ads [][]byte, plaintext []byte) []byte {
	d := cmac(block, make([]byte, blockSize))
	for _, ad := range ads {
		d = xor(dbl(d), cmac(block, ad))
	}
	var t []byte
	if len(plaintext) >= blockSize {
		t = xorend(plaintext, d)
	} else {
		t = xor(dbl(d), pad(plaintext))
	}
	return cmac(block, t)
}

func splitKey(key []byte) (cipher.Block, cipher.Block, error) {
	if len(key)%2 != 0 {
		return nil, nil, fmt.Errorf("siv: key length %d not even", len(key))
	}
	half := len(key) / 2
	macBlock, err := aes.NewCipher(key[:half])
	if err != nil {
		return nil, nil, fmt.Errorf("siv: mac key: %w", err)
	}
	ctrBlock, err := aes.NewCipher(key[half:])
	if err != nil {
		return nil, nil, fmt.Errorf("siv: ctr key: %w", err)
	}
	return macBlock, ctrBlock, nil
}

func ctrIV(v []byte) []byte {
	q := make([]byte, blockSize)
	copy(q, v)
	q[8] &= 0x7f
	q[12] &= 0x7f
	return q
}

func SIVDecrypt(key, in []byte, ads [][]byte) ([]byte, error) {
	if len(in) < blockSize {
		return nil, errors.New("siv: input shorter than one block")
	}
	macBlock, ctrBlock, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	v := in[:blockSize]
	c := in[blockSize:]
	m := make([]byte, len(c))
	cipher.NewCTR(ctrBlock, ctrIV(v)).XORKeyStream(m, c)
	t := s2v(macBlock, ads, m)
	if subtle.ConstantTimeCompare(t, v) != 1 {
		return nil, errors.New("siv: authentication failed")
	}
	return m, nil
}

func SIVEncrypt(key, plaintext []byte, ads [][]byte) ([]byte, error) {
	macBlock, ctrBlock, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	v := s2v(macBlock, ads, plaintext)
	c := make([]byte, len(plaintext))
	cipher.NewCTR(ctrBlock, ctrIV(v)).XORKeyStream(c, plaintext)
	return append(append([]byte{}, v...), c...), nil
}
