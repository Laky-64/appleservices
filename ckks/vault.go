package ckks

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"sync"

	"howett.net/plist"

	"github.com/Laky-64/appleservices/cloudkit"
	"github.com/Laky-64/appleservices/internal/protobuf"
	"github.com/Laky-64/appleservices/keychain"
	"github.com/Laky-64/appleservices/octagon"
)

type Vault struct {
	ck            *cloudkit.Client
	sponsorEnc    *ecdsa.PrivateKey
	sponsorPeerID string

	mu    sync.Mutex
	zones map[string]*zoneKeys
}

type zoneKeys struct {
	tlk       []byte
	classKeys [][]byte
}

func OpenVault(ck *cloudkit.Client, sponsorEnc *ecdsa.PrivateKey, sponsorPeerID string) *Vault {
	return &Vault{
		ck:            ck,
		sponsorEnc:    sponsorEnc,
		sponsorPeerID: sponsorPeerID,
		zones:         map[string]*zoneKeys{},
	}
}

func (v *Vault) Items(view string) ([]keychain.Item, error) {
	body, err := v.ck.RecordSyncZone(view)
	if err != nil {
		return nil, fmt.Errorf("ckks: fetch view %q: %w", view, err)
	}
	records, err := ParseZone(body)
	if err != nil {
		return nil, fmt.Errorf("ckks: parse view %q: %w", view, err)
	}

	keys, err := v.zoneKeysFor(view, records)
	if err != nil {
		return nil, err
	}

	var items []keychain.Item
	for _, rec := range records {
		if rec.Type != "item" {
			continue
		}
		item, err := decryptItemRecord(rec, keys.classKeys)
		if err != nil {
			return nil, fmt.Errorf("ckks: item %q: %w", rec.Name, err)
		}
		items = append(items, item)
	}
	return items, nil
}

func (v *Vault) zoneKeysFor(view string, records []Record) (*zoneKeys, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if zk, ok := v.zones[view]; ok {
		return zk, nil
	}

	tlk, err := v.unwrapTLK(records)
	if err != nil {
		return nil, err
	}
	classKeys, err := deriveClassKeys(records, tlk)
	if err != nil {
		return nil, err
	}
	zk := &zoneKeys{tlk: tlk, classKeys: classKeys}
	v.zones[view] = zk
	return zk, nil
}

func (v *Vault) unwrapTLK(records []Record) ([]byte, error) {
	for _, rec := range records {
		if rec.Type != "tlkshare" {
			continue
		}
		if string(rec.Fields["receiver"].Bytes) != v.sponsorPeerID {
			continue
		}
		blob, err := extractECIES(string(rec.Fields["wrappedkey"].Bytes))
		if err != nil {
			return nil, fmt.Errorf("ckks: tlkshare for sponsor: %w", err)
		}
		ckksKey, err := octagon.UnwrapECIES(v.sponsorEnc, blob)
		if err != nil {
			return nil, fmt.Errorf("ckks: unwrap TLKShare ECIES: %w", err)
		}
		return tlkKeyFromCKKSKey(ckksKey)
	}
	return nil, fmt.Errorf("ckks: no TLKShare for sponsor peer %q", v.sponsorPeerID)
}

func tlkKeyFromCKKSKey(pt []byte) ([]byte, error) {
	if fields, err := protobuf.ReadFields(pt); err == nil {
		for _, f := range fields {
			if f.Number == 4 && f.WireType == protobuf.WireBytes && len(f.Bytes) == KeyLen {
				return f.Bytes, nil
			}
		}
	}
	if len(pt) == KeyLen {
		return pt, nil
	}
	return nil, fmt.Errorf("ckks: CKKSKey has no 64-byte key at field 4 (plaintext %dB)", len(pt))
}

func deriveClassKeys(records []Record, tlk []byte) ([][]byte, error) {
	var classKeys [][]byte
	for _, rec := range records {
		if rec.Type != "synckey" {
			continue
		}
		class := string(rec.Fields["class"].Bytes)
		if class != "classA" && class != "classC" {
			continue
		}
		wrapped, err := base64.StdEncoding.DecodeString(string(rec.Fields["wrappedkey"].Bytes))
		if err != nil {
			return nil, fmt.Errorf("ckks: %s synckey wrappedkey base64: %w", class, err)
		}
		key, err := UnwrapKey(tlk, wrapped)
		if err != nil {
			return nil, fmt.Errorf("ckks: unwrap %s class key: %w", class, err)
		}
		classKeys = append(classKeys, key)
	}
	if len(classKeys) == 0 {
		return nil, fmt.Errorf("ckks: no class keys in zone")
	}
	return classKeys, nil
}

func decryptItemRecord(rec Record, classKeys [][]byte) (keychain.Item, error) {
	wrapped, err := base64.StdEncoding.DecodeString(string(rec.Fields["wrappedkey"].Bytes))
	if err != nil {
		return keychain.Item{}, fmt.Errorf("wrappedkey base64: %w", err)
	}
	itemKey, err := selectItemKey(classKeys, wrapped)
	if err != nil {
		return keychain.Item{}, err
	}

	aad, err := buildItemAAD(rec)
	if err != nil {
		return keychain.Item{}, err
	}
	padded, err := DecryptItem(itemKey, rec.Fields["data"].Bytes, aad)
	if err != nil {
		return keychain.Item{}, fmt.Errorf("decrypt: %w", err)
	}
	return parseItemPlist(trimPadding(padded))
}

func selectItemKey(classKeys [][]byte, wrapped []byte) ([]byte, error) {
	for _, ck := range classKeys {
		if key, err := UnwrapKey(ck, wrapped); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("no class key unwraps the per-item key")
}

func trimPadding(b []byte) []byte {
	n := len(b)
	for n > 0 && b[n-1] == 0x00 {
		n--
	}
	if n > 0 && b[n-1] == 0x80 {
		n--
	}
	return b[:n]
}

func parseItemPlist(data []byte) (keychain.Item, error) {
	var doc map[string]any
	if _, err := plist.Unmarshal(data, &doc); err != nil {
		return keychain.Item{}, fmt.Errorf("attribute plist: %w", err)
	}
	item := keychain.Item{
		Class: asString(doc["class"]),
		Agrp:  asString(doc["agrp"]),
		Srvr:  asString(doc["srvr"]),
		Acct:  asString(doc["acct"]),
		Labl:  asString(doc["labl"]),
		Attrs: doc,
	}
	if d, ok := doc["v_Data"].([]byte); ok {
		item.Data = d
	}
	return item, nil
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
