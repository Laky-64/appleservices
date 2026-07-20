package octagon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/Laky-64/appleservices/internal/protobuf"
)

const escrowSymmetricKeyLen = 32

func deriveEscrowSymmetricKey(secret []byte, bottleSalt string) ([]byte, error) {
	reader := hkdf.New(sha512.New384, secret, []byte(bottleSalt), []byte("Escrow Symmetric Key"))
	key := make([]byte, escrowSymmetricKeyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

type authenticatedCiphertext struct {
	Ciphertext []byte
	AuthCode   []byte
	IV         []byte
}

func unmarshalAuthCiphertext(data []byte) (authenticatedCiphertext, error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return authenticatedCiphertext{}, err
	}
	var a authenticatedCiphertext
	for _, f := range fields {
		switch f.Number {
		case 1:
			a.Ciphertext = f.Bytes
		case 2:
			a.AuthCode = f.Bytes
		case 3:
			a.IV = f.Bytes
		}
	}
	return a, nil
}

func marshalAuthCiphertext(a authenticatedCiphertext) []byte {
	w := protobuf.NewWriter()
	w.WriteBytes(1, a.Ciphertext)
	w.WriteBytes(2, a.AuthCode)
	w.WriteBytes(3, a.IV)
	return w.Bytes()
}

type otBottle struct {
	PeerID                 string
	BottleID               string
	EscrowedSigningSPKI    []byte
	EscrowedEncryptionSPKI []byte
	PeerSigningSPKI        []byte
	PeerEncryptionSPKI     []byte
	Contents               authenticatedCiphertext
}

func unmarshalOTBottle(data []byte) (otBottle, error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return otBottle{}, err
	}
	var b otBottle
	for _, f := range fields {
		switch f.Number {
		case 1:
			b.PeerID = string(f.Bytes)
		case 2:
			b.BottleID = string(f.Bytes)
		case 8:
			b.EscrowedSigningSPKI = f.Bytes
		case 9:
			b.EscrowedEncryptionSPKI = f.Bytes
		case 10:
			b.PeerSigningSPKI = f.Bytes
		case 11:
			b.PeerEncryptionSPKI = f.Bytes
		case 12:
			c, err := unmarshalAuthCiphertext(f.Bytes)
			if err != nil {
				return otBottle{}, err
			}
			b.Contents = c
		}
	}
	return b, nil
}

func marshalOTBottle(b otBottle) []byte {
	w := protobuf.NewWriter()
	if b.PeerID != "" {
		w.WriteBytes(1, []byte(b.PeerID))
	}
	if b.BottleID != "" {
		w.WriteBytes(2, []byte(b.BottleID))
	}
	if len(b.EscrowedSigningSPKI) > 0 {
		w.WriteBytes(8, b.EscrowedSigningSPKI)
	}
	if len(b.EscrowedEncryptionSPKI) > 0 {
		w.WriteBytes(9, b.EscrowedEncryptionSPKI)
	}
	if len(b.PeerSigningSPKI) > 0 {
		w.WriteBytes(10, b.PeerSigningSPKI)
	}
	if len(b.PeerEncryptionSPKI) > 0 {
		w.WriteBytes(11, b.PeerEncryptionSPKI)
	}
	w.WriteBytes(12, marshalAuthCiphertext(b.Contents))
	return w.Bytes()
}

func otPrivateKeyData(data []byte) ([]byte, error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return nil, err
	}
	for _, f := range fields {
		if f.Number == 2 {
			return f.Bytes, nil
		}
	}
	return nil, fmt.Errorf("octagon: OTPrivateKey missing keyData")
}

func marshalOTPrivateKey(keyData []byte) []byte {
	w := protobuf.NewWriter()
	w.WriteVarint(1, 1)
	w.WriteBytes(2, keyData)
	return w.Bytes()
}

func unmarshalBottleContents(data []byte) (signingKeyData, encryptionKeyData []byte, err error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range fields {
		switch f.Number {
		case 3:
			if signingKeyData, err = otPrivateKeyData(f.Bytes); err != nil {
				return nil, nil, err
			}
		case 4:
			if encryptionKeyData, err = otPrivateKeyData(f.Bytes); err != nil {
				return nil, nil, err
			}
		}
	}
	if signingKeyData == nil || encryptionKeyData == nil {
		return nil, nil, fmt.Errorf("octagon: bottle contents missing peer keys")
	}
	return signingKeyData, encryptionKeyData, nil
}

func marshalBottleContents(signingKeyData, encryptionKeyData []byte) []byte {
	w := protobuf.NewWriter()
	w.WriteBytes(3, marshalOTPrivateKey(signingKeyData))
	w.WriteBytes(4, marshalOTPrivateKey(encryptionKeyData))
	return w.Bytes()
}

func parseP384KeyData(keyData []byte) (*ecdsa.PrivateKey, error) {
	const p384KeyDataLen = 1 + 48*3
	if len(keyData) != p384KeyDataLen || keyData[0] != 0x04 {
		return nil, fmt.Errorf("octagon: unexpected P-384 keyData (len=%d)", len(keyData))
	}
	d := keyData[1+48*2:]
	return ecdsa.ParseRawPrivateKey(elliptic.P384(), d)
}

func p384KeyData(k *ecdsa.PrivateKey) ([]byte, error) {
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	priv, err := k.Bytes()
	if err != nil {
		return nil, err
	}
	return append(pub, priv...), nil
}

func DecryptBottle(secret []byte, bottleSalt string, bottleBytes []byte) (peerSigning, peerEncryption *ecdsa.PrivateKey, err error) {
	bottle, err := unmarshalOTBottle(bottleBytes)
	if err != nil {
		return nil, nil, err
	}
	symKey, err := deriveEscrowSymmetricKey(secret, bottleSalt)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aesGCMOpen(symKey, bottle.Contents.IV, bottle.Contents.Ciphertext, bottle.Contents.AuthCode)
	if err != nil {
		return nil, nil, fmt.Errorf("octagon: bottle decrypt: %w", err)
	}
	sigData, encData, err := unmarshalBottleContents(plaintext)
	if err != nil {
		return nil, nil, err
	}
	if peerSigning, err = parseP384KeyData(sigData); err != nil {
		return nil, nil, fmt.Errorf("octagon: peer signing key: %w", err)
	}
	if peerEncryption, err = parseP384KeyData(encData); err != nil {
		return nil, nil, fmt.Errorf("octagon: peer encryption key: %w", err)
	}
	return peerSigning, peerEncryption, nil
}

func aesGCMOpen(key, iv, ciphertext, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, append(append([]byte{}, ciphertext...), tag...), nil)
}

func aesGCMSeal(key, iv, plaintext []byte) (ciphertext, tag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, nil, err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	tagLen := gcm.Overhead()
	return sealed[:len(sealed)-tagLen], sealed[len(sealed)-tagLen:], nil
}
