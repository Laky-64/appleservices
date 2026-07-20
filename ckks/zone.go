package ckks

import (
	"fmt"

	"github.com/Laky-64/appleservices/internal/protobuf"
	"github.com/Laky-64/appleservices/octagon"
)

func ParseZone(recordSyncBody []byte) ([]Record, error) {
	data := recordSyncBody
	if msg, err := octagon.UnframeCodeInvoke(recordSyncBody); err == nil {
		data = msg
	}

	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return nil, fmt.Errorf("ckks: parsing record/sync response: %w", err)
	}

	var zoneRecords []byte
	for _, f := range fields {
		if f.Number == 213 && f.WireType == protobuf.WireBytes {
			zoneRecords = f.Bytes
		}
	}
	if zoneRecords == nil {
		return nil, fmt.Errorf("ckks: no zone records (field 213) in record/sync response")
	}

	recFields, err := protobuf.ReadFields(zoneRecords)
	if err != nil {
		return nil, fmt.Errorf("ckks: parsing zone records: %w", err)
	}

	var records []Record
	for _, f := range recFields {
		if f.Number != 1 || f.WireType != protobuf.WireBytes {
			continue
		}
		rec, err := parseRecord(f.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ckks: parsing zone record: %w", err)
		}
		records = append(records, rec)
	}
	return records, nil
}
