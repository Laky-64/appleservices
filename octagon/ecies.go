package octagon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	p384PointLen  = 97
	eciesKDFLen   = 48
	eciesNonceLen = 16
)

func x963KDFSHA256(z, sharedInfo []byte, outLen int) []byte {
	out := make([]byte, 0, ((outLen+31)/32)*32)
	var counter uint32 = 1
	var c [4]byte
	for len(out) < outLen {
		h := sha256.New()
		h.Write(z)
		binary.BigEndian.PutUint32(c[:], counter)
		h.Write(c[:])
		h.Write(sharedInfo)
		out = h.Sum(out)
		counter++
	}
	return out[:outLen]
}

func WrapECIES(recipientPub *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	pub, err := recipientPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("recipient public key: %w", err)
	}
	ephPriv, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral keygen: %w", err)
	}
	ephPub := ephPriv.PublicKey().Bytes()
	z, err := ephPriv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	gcm, nonce, err := eciesGCM(z, ephPub)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	return append(ephPub, sealed...), nil
}

func UnwrapECIES(recipientPriv *ecdsa.PrivateKey, blob []byte) ([]byte, error) {
	if len(blob) < p384PointLen+16 {
		return nil, fmt.Errorf("ecies blob too short: %d bytes", len(blob))
	}
	priv, err := recipientPriv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("recipient private key: %w", err)
	}
	ephPubBytes := blob[:p384PointLen]
	ephPub, err := ecdh.P384().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("ephemeral public key: %w", err)
	}
	z, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	gcm, nonce, err := eciesGCM(z, ephPubBytes)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, blob[p384PointLen:], nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return plaintext, nil
}

func eciesGCM(z, ephPub []byte) (cipher.AEAD, []byte, error) {
	material := x963KDFSHA256(z, ephPub, eciesKDFLen)
	block, err := aes.NewCipher(material[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, eciesNonceLen)
	if err != nil {
		return nil, nil, fmt.Errorf("gcm: %w", err)
	}
	return gcm, material[32:eciesKDFLen], nil
}
