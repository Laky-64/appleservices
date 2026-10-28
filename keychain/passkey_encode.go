package keychain

import (
	"errors"
	"fmt"
	"time"

	"howett.net/plist"
)

const (
	agrpWebauthn = "com.apple.webkit.webauthn"
	p256Len      = 32
)

var appleEpoch = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

func EncodePasskeyItem(pk Passkey) ([]byte, error) {
	if pk.PrivateKey == nil {
		return nil, errors.New("keychain: passkey has no private key")
	}
	if pk.RelyingParty == "" || len(pk.CredentialID) == 0 || len(pk.UserHandle) == 0 {
		return nil, errors.New("keychain: passkey needs a relying party, credential id and user handle")
	}
	pub, err := pk.PrivateKey.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("keychain: passkey public key: %w", err)
	}
	d, err := pk.PrivateKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("keychain: passkey private key: %w", err)
	}
	if len(pub) != 1+2*p256Len || len(d) != p256Len {
		return nil, errors.New("keychain: passkey is not a P-256 key")
	}
	created, modified := pk.Created.UTC(), pk.Modified.UTC()
	if created.IsZero() {
		created = time.Now().UTC()
	}
	if modified.IsZero() {
		modified = created
	}
	attrs := map[string]any{
		"class":  "keys",
		"agrp":   agrpWebauthn,
		"pdmn":   "ak",
		"kcls":   uint64(1),
		"type":   uint64(73),
		"bsiz":   uint64(256),
		"esiz":   uint64(256),
		"perm":   uint64(1),
		"priv":   uint64(1),
		"modi":   uint64(1),
		"sign":   uint64(1),
		"decr":   uint64(1),
		"drve":   uint64(1),
		"unwp":   uint64(1),
		"extr":   uint64(1),
		"encr":   uint64(0),
		"vrfy":   uint64(0),
		"wrap":   uint64(0),
		"tomb":   uint64(0),
		"asen":   uint64(0),
		"crtr":   uint64(0),
		"next":   uint64(0),
		"sens":   uint64(0),
		"snrc":   uint64(0),
		"vyrc":   uint64(0),
		"edat":   appleEpoch,
		"sdat":   appleEpoch,
		"musr":   []byte{},
		"labl":   pk.RelyingParty,
		"alis":   pk.CredentialID,
		"klbl":   pk.CredentialID,
		"atag":   encodeAtag(pk.UserHandle, pk.UserName, pk.DisplayName),
		"v_Data": append(pub, d...),
		"cdat":   created,
		"mdat":   modified,
	}
	data, err := plist.Marshal(attrs, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("keychain: encode passkey item: %w", err)
	}
	return data, nil
}

func encodeAtag(userHandle []byte, userName, displayName string) []byte {
	out := []byte{0xa3}
	out = appendCBORHead(out, 3, 2)
	out = append(out, "id"...)
	out = appendCBORHead(out, 2, len(userHandle))
	out = append(out, userHandle...)
	out = appendCBORHead(out, 3, 4)
	out = append(out, "name"...)
	out = appendCBORHead(out, 3, len(userName))
	out = append(out, userName...)
	out = appendCBORHead(out, 3, 11)
	out = append(out, "displayName"...)
	out = appendCBORHead(out, 3, len(displayName))
	return append(out, displayName...)
}

func appendCBORHead(out []byte, major byte, n int) []byte {
	switch {
	case n < 24:
		return append(out, major<<5|byte(n))
	case n < 1<<8:
		return append(out, major<<5|24, byte(n))
	case n < 1<<16:
		return append(out, major<<5|25, byte(n>>8), byte(n))
	default:
		return append(out, major<<5|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}
