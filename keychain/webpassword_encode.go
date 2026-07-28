package keychain

import (
	"fmt"
	"time"

	"howett.net/plist"
)

const metadataType = 1835626085

func inetAttrs(agrp, srvr, acct string, vData []byte) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"class":  "inet",
		"agrp":   agrp,
		"srvr":   srvr,
		"acct":   acct,
		"v_Data": vData,
		"pdmn":   "ak",
		"atyp":   "form",
		"ptcl":   "htps",
		"port":   uint64(0),
		"path":   "",
		"sdmn":   "",
		"musr":   []byte{},
		"tomb":   uint64(0),
		"cdat":   now,
		"mdat":   now,
	}
}

func EncodeWebPasswordItem(srvr, username, password string) ([]byte, error) {
	attrs := inetAttrs("com.apple.cfnetwork", srvr, username, []byte(password))
	attrs["desc"] = "Web form password"
	attrs["labl"] = fmt.Sprintf("%s (%s)", srvr, username)
	data, err := plist.Marshal(attrs, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("keychain: encode web password item: %w", err)
	}
	return data, nil
}

func EncodeMetadataItem(srvr, username, title, note string) ([]byte, error) {
	metadata := map[string]any{
		"title": []byte(title),
		"s_as":  []any{},
	}
	if note != "" {
		metadata["notes"] = []byte(note)
	}
	inner, err := plist.Marshal(metadata, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("keychain: encode metadata payload: %w", err)
	}
	attrs := inetAttrs("com.apple.password-manager", srvr, username, inner)
	attrs["type"] = uint64(metadataType)
	attrs["desc"] = "Password Manager Metadata"
	attrs["labl"] = fmt.Sprintf("Password Manager Metadata: %s (%s)", srvr, username)
	data, err := plist.Marshal(attrs, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("keychain: encode metadata item: %w", err)
	}
	return data, nil
}
