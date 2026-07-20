package ckks

import (
	"encoding/base64"
	"fmt"

	"howett.net/plist"
)

const (
	ephPubLen = 97
	iesTagLen = 16
)

func extractECIES(wrappedKeyB64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(wrappedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("ckks: tlkshare wrappedkey base64: %w", err)
	}

	var arch struct {
		Top     map[string]plist.UID `plist:"$top"`
		Objects []any                `plist:"$objects"`
	}
	if _, err := plist.Unmarshal(raw, &arch); err != nil {
		return nil, fmt.Errorf("ckks: tlkshare wrappedkey bplist: %w", err)
	}

	obj := func(key string) any {
		u, ok := arch.Top[key]
		if !ok || uint64(u) >= uint64(len(arch.Objects)) {
			return nil
		}
		return arch.Objects[u]
	}
	ephPub := archiveBytes(obj("SFEphemeralSenderPublicKeyExternaRepresentation"))
	ct := archiveBytes(obj("SFCiphertext"))
	tag := archiveBytes(obj("SFIESAuthenticationCode"))

	ctLen := len(ct)
	for ctLen > 0 && ct[ctLen-1] == 0 {
		ctLen--
	}
	ct = ct[:ctLen]

	if len(ephPub) != ephPubLen || len(ct) == 0 || len(tag) != iesTagLen {
		return nil, fmt.Errorf("ckks: tlkshare ECIES parts: ephPub=%d ct=%d tag=%d",
			len(ephPub), len(ct), len(tag))
	}

	blob := make([]byte, 0, len(ephPub)+len(ct)+len(tag))
	blob = append(blob, ephPub...)
	blob = append(blob, ct...)
	blob = append(blob, tag...)
	return blob, nil
}

func archiveBytes(v any) []byte {
	switch t := v.(type) {
	case []byte:
		return t
	case map[string]any:
		if b, ok := t["NS.data"].([]byte); ok {
			return b
		}
	}
	return nil
}
