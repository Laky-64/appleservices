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
	inner := map[string]any{
		"title": []byte(title),
		"s_as":  []any{},
	}
	if note != "" {
		inner["notes"] = []byte(note)
	}
	return EncodeCompanionItem(srvr, username, inner)
}

func EncodeCompanionInner(inner map[string]any) ([]byte, error) {
	data, err := plist.Marshal(inner, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("keychain: encode companion payload: %w", err)
	}
	return data, nil
}

func EncodeCompanionItem(srvr, username string, inner map[string]any) ([]byte, error) {
	data, err := EncodeCompanionInner(inner)
	if err != nil {
		return nil, err
	}
	return EncodeCompanionData(srvr, username, data)
}

func EncodeCompanionData(srvr, username string, data []byte) ([]byte, error) {
	attrs := inetAttrs("com.apple.password-manager", srvr, username, data)
	attrs["type"] = uint64(metadataType)
	attrs["desc"] = "Password Manager Metadata"
	attrs["labl"] = fmt.Sprintf("Password Manager Metadata: %s (%s)", srvr, username)
	return plist.Marshal(attrs, plist.BinaryFormat)
}

func DecodeCompanionInner(data []byte) map[string]any {
	return parsePlist(data)
}

func EncodeItemWithSecret(attrs map[string]any, secret []byte) ([]byte, error) {
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	out["v_Data"] = secret
	delete(out, "sha1")
	return plist.Marshal(out, plist.BinaryFormat)
}

func EncodeItemRenamed(attrs map[string]any, newSrvr, newAcct string, secret []byte) ([]byte, error) {
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	out["srvr"] = newSrvr
	out["acct"] = newAcct
	out["v_Data"] = secret
	delete(out, "sha1")
	return plist.Marshal(out, plist.BinaryFormat)
}
