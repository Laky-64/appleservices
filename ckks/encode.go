package ckks

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"howett.net/plist"

	"github.com/Laky-64/appleservices/cloudkit"
	"github.com/Laky-64/appleservices/internal/protobuf"
	"github.com/Laky-64/appleservices/internal/uuid"
)

const (
	idTypeRecord     = 1
	idTypeRecordZone = 6
	idTypeUser       = 7

	refTypeOwning = 1
)

func identifier(name string, typ int) []byte {
	w := protobuf.NewWriter()
	w.WriteBytes(1, []byte(name))
	w.WriteVarint(2, uint64(typ))
	return w.Bytes()
}

func recordZoneIdentifier(zone, owner string) []byte {
	w := protobuf.NewWriter()
	w.WriteBytes(1, identifier(zone, idTypeRecordZone))
	w.WriteBytes(2, identifier(owner, idTypeUser))
	w.WriteVarint(3, 1)
	return w.Bytes()
}

func recordIdentifier(name, zone, owner string) []byte {
	w := protobuf.NewWriter()
	w.WriteBytes(1, identifier(name, idTypeRecord))
	w.WriteBytes(2, recordZoneIdentifier(zone, owner))
	return w.Bytes()
}

func encodeReference(targetUUID, zone, owner string) []byte {
	w := protobuf.NewWriter()
	w.WriteVarint(1, refTypeOwning)
	w.WriteBytes(2, recordIdentifier(targetUUID, zone, owner))
	return w.Bytes()
}

func encodeCKValue(v CKValue) []byte {
	w := protobuf.NewWriter()
	w.WriteVarint(1, uint64(v.Type))
	switch v.Type {
	case 1:
		w.WriteBytes(2, v.Bytes)
	case 3:
		w.WriteBytes(7, v.Bytes)
	case 5:
		w.WriteBytes(9, v.Bytes)
	case 7:
		w.WriteVarint(4, uint64(v.Int))
	}
	return w.Bytes()
}

func encodeNamedField(name string, v CKValue) []byte {
	nm := protobuf.NewWriter()
	nm.WriteBytes(1, []byte(name))

	w := protobuf.NewWriter()
	w.WriteBytes(1, nm.Bytes())
	w.WriteBytes(2, encodeCKValue(v))
	return w.Bytes()
}

var fieldOrder = []string{"data", "encver", "gen", "parentkeyref", "server_suggestDeletion", "server_wascurrent", "uploadver", "wrappedkey"}

func encodeRecord(r Record, zone, owner string) []byte {
	typ := protobuf.NewWriter()
	typ.WriteBytes(1, []byte(r.Type))

	w := protobuf.NewWriter()
	w.WriteBytes(2, recordIdentifier(r.Name, zone, owner))
	w.WriteBytes(3, typ.Bytes())
	for _, name := range fieldOrder {
		if v, ok := r.Fields[name]; ok {
			w.WriteBytes(7, encodeNamedField(name, v))
		}
	}
	return w.Bytes()
}

const uploadTag = "appleservices"

func EncodeItemRecord(zoneName, owner string, classCKey []byte, classCUUID string, attrs []byte) (itemUUID string, recordSaveRequest []byte, err error) {
	itemUUID = uuid.New()
	record, err := buildItemRecord(zoneName, owner, classCKey, classCUUID, itemUUID, attrs)
	if err != nil {
		return "", nil, err
	}
	req := protobuf.NewWriter()
	req.WriteBytes(1, record)
	req.WriteVarint(6, 2)
	return itemUUID, req.Bytes(), nil
}

func EncodeItemRecordUpdate(zoneName, owner string, classCKey []byte, classCUUID, itemUUID, etag string, attrs []byte) ([]byte, error) {
	record, err := buildItemRecord(zoneName, owner, classCKey, classCUUID, itemUUID, attrs)
	if err != nil {
		return nil, err
	}
	req := protobuf.NewWriter()
	req.WriteBytes(1, record)
	if etag != "" {
		req.WriteBytes(4, []byte(etag))
	}
	req.WriteVarint(6, 3)
	return req.Bytes(), nil
}

func buildItemRecord(zoneName, owner string, classCKey []byte, classCUUID, itemUUID string, attrs []byte) ([]byte, error) {
	if len(classCKey) != KeyLen {
		return nil, fmt.Errorf("ckks: classC key length %d, want %d", len(classCKey), KeyLen)
	}

	itemKey := make([]byte, KeyLen)
	if _, err := rand.Read(itemKey); err != nil {
		return nil, fmt.Errorf("ckks: item key: %w", err)
	}

	parentRef := encodeReference(classCUUID, zoneName, owner)

	rec := Record{
		Type: "item",
		Name: itemUUID,
		Fields: map[string]CKValue{
			"encver":       {Type: 7, Int: 2},
			"gen":          {Type: 7, Int: 0},
			"parentkeyref": {Type: 5, Bytes: parentRef},
		},
	}
	aad, err := buildItemAAD(rec)
	if err != nil {
		return nil, err
	}

	data, err := EncryptItem(itemKey, padItem(attrs), aad)
	if err != nil {
		return nil, fmt.Errorf("ckks: encrypt item: %w", err)
	}
	wrapped, err := WrapKey(classCKey, itemKey)
	if err != nil {
		return nil, fmt.Errorf("ckks: wrap item key: %w", err)
	}

	rec.Fields["data"] = CKValue{Type: 1, Bytes: data}
	rec.Fields["wrappedkey"] = CKValue{Type: 3, Bytes: []byte(base64.StdEncoding.EncodeToString(wrapped))}
	rec.Fields["uploadver"] = CKValue{Type: 3, Bytes: []byte(uploadTag)}
	rec.Fields["server_wascurrent"] = CKValue{Type: 7, Int: 0}
	rec.Fields["server_suggestDeletion"] = CKValue{Type: 7, Int: 0}

	return encodeRecord(rec, zoneName, owner), nil
}

func EncodeRecordDelete(recordName, zone, owner, etag string) []byte {
	w := protobuf.NewWriter()
	w.WriteBytes(1, recordIdentifier(recordName, zone, owner))
	if etag != "" {
		w.WriteBytes(2, []byte(etag))
	}
	return w.Bytes()
}

func (v *Vault) AddItem(view string, attrs []byte) (itemUUID string, sr cloudkit.SaveResult, err error) {
	body, err := v.ck.RecordSyncZone(view)
	if err != nil {
		return "", cloudkit.SaveResult{}, fmt.Errorf("ckks: fetch view %q: %w", view, err)
	}
	records, err := ParseZone(body)
	if err != nil {
		return "", cloudkit.SaveResult{}, fmt.Errorf("ckks: parse view %q: %w", view, err)
	}
	zk, err := v.zoneKeysFor(view, records)
	if err != nil {
		return "", cloudkit.SaveResult{}, err
	}
	className := classForPdmn(pdmnOf(attrs))
	ck, ok := zk.classes[className]
	if !ok || len(ck.key) != KeyLen || ck.uuid == "" {
		return "", cloudkit.SaveResult{}, fmt.Errorf("ckks: view %q has no %s key for writes", view, className)
	}
	itemUUID, req, err := EncodeItemRecord(view, v.ck.UserID(), ck.key, ck.uuid, attrs)
	if err != nil {
		return "", cloudkit.SaveResult{}, err
	}
	sr, err = v.ck.RecordSave(req)
	return itemUUID, sr, err
}

func (v *Vault) UpdateItem(view, recordName, etag string, attrs []byte) (cloudkit.SaveResult, error) {
	body, err := v.ck.RecordSyncZone(view)
	if err != nil {
		return cloudkit.SaveResult{}, fmt.Errorf("ckks: fetch view %q: %w", view, err)
	}
	records, err := ParseZone(body)
	if err != nil {
		return cloudkit.SaveResult{}, fmt.Errorf("ckks: parse view %q: %w", view, err)
	}
	zk, err := v.zoneKeysFor(view, records)
	if err != nil {
		return cloudkit.SaveResult{}, err
	}
	className := classForPdmn(pdmnOf(attrs))
	ck, ok := zk.classes[className]
	if !ok || len(ck.key) != KeyLen || ck.uuid == "" {
		return cloudkit.SaveResult{}, fmt.Errorf("ckks: view %q has no %s key for writes", view, className)
	}
	req, err := EncodeItemRecordUpdate(view, v.ck.UserID(), ck.key, ck.uuid, recordName, etag, attrs)
	if err != nil {
		return cloudkit.SaveResult{}, err
	}
	return v.ck.RecordSave(req)
}

func pdmnOf(attrs []byte) string {
	var m map[string]any
	if _, err := plist.Unmarshal(attrs, &m); err == nil {
		if s, ok := m["pdmn"].(string); ok {
			return s
		}
	}
	return ""
}

func classForPdmn(pdmn string) string {
	switch pdmn {
	case "ak", "aku":
		return "classA"
	default:
		return "classC"
	}
}

func padItem(plaintext []byte) []byte {
	padLen := blockSize - (len(plaintext) % blockSize)
	out := make([]byte, len(plaintext)+padLen)
	copy(out, plaintext)
	out[len(plaintext)] = 0x80
	return out
}
