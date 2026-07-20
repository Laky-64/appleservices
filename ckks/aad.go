package ckks

import (
	"encoding/binary"
	"fmt"
)

func buildItemAAD(item Record) ([][]byte, error) {
	var aad [][]byte

	aad = append(aad, []byte(item.Name))

	if v, ok := item.Fields["encver"]; ok {
		aad = append(aad, leInt64(v.Int))
	}
	if v, ok := item.Fields["gen"]; ok {
		aad = append(aad, leInt64(v.Int))
	}

	if v, ok := item.Fields["pcspublicidentity"]; ok {
		aad = append(aad, v.Bytes)
	}
	if v, ok := item.Fields["pcspublickey"]; ok {
		aad = append(aad, v.Bytes)
	}
	if v, ok := item.Fields["pcsservice"]; ok {
		aad = append(aad, leInt64(v.Int))
	}

	if v, ok := item.Fields["parentkeyref"]; ok {
		parentUUID, err := refTargetName(v.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ckks: resolving parentkeyref: %w", err)
		}
		aad = append(aad, []byte(parentUUID))
	}

	return aad, nil
}

func leInt64(v int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}
