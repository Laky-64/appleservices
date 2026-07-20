package ckks

import (
	"fmt"

	"github.com/Laky-64/appleservices/internal/protobuf"
)

type CKValue struct {
	Type  int
	Bytes []byte
	Int   int64
}

type Record struct {
	Type   string
	Name   string
	Fields map[string]CKValue
}

func parseRecord(rec []byte) (Record, error) {
	fields, err := protobuf.ReadFields(rec)
	if err != nil {
		return Record{}, fmt.Errorf("ckks: parsing record: %w", err)
	}
	var body, recordID []byte
	for _, f := range fields {
		switch {
		case f.Number == 5 && f.WireType == protobuf.WireBytes:
			body = f.Bytes
		case f.Number == 1 && f.WireType == protobuf.WireBytes:
			recordID = f.Bytes
		}
	}
	if body == nil {
		return Record{}, fmt.Errorf("ckks: record missing body (field 5)")
	}
	name, err := recordNameFromID(recordID)
	if err != nil {
		return Record{}, fmt.Errorf("ckks: parsing record name: %w", err)
	}

	inner, err := protobuf.ReadFields(body)
	if err != nil {
		return Record{}, fmt.Errorf("ckks: parsing record body: %w", err)
	}

	out := Record{Name: name, Fields: map[string]CKValue{}}
	for _, f := range inner {
		switch f.Number {
		case 3:
			t, err := protobuf.ReadFields(f.Bytes)
			if err != nil {
				return Record{}, fmt.Errorf("ckks: parsing record type: %w", err)
			}
			for _, tf := range t {
				if tf.Number == 1 && tf.WireType == protobuf.WireBytes {
					out.Type = string(tf.Bytes)
				}
			}
		case 7:
			name, val, ok, err := parseNamedField(f.Bytes)
			if err != nil {
				return Record{}, fmt.Errorf("ckks: parsing named field: %w", err)
			}
			if ok {
				out.Fields[name] = val
			}
		}
	}
	return out, nil
}

func recordNameFromID(id []byte) (string, error) {
	if len(id) == 0 {
		return "", nil
	}
	return refInnerName(id)
}

func refInnerName(msg []byte) (string, error) {
	fields, err := protobuf.ReadFields(msg)
	if err != nil {
		return "", err
	}
	for _, f := range fields {
		if f.Number != 1 || f.WireType != protobuf.WireBytes {
			continue
		}
		inner, err := protobuf.ReadFields(f.Bytes)
		if err != nil {
			return "", err
		}
		for _, in := range inner {
			if in.Number == 1 && in.WireType == protobuf.WireBytes {
				return string(in.Bytes), nil
			}
		}
	}
	return "", nil
}

func refTargetName(ckref []byte) (string, error) {
	fields, err := protobuf.ReadFields(ckref)
	if err != nil {
		return "", err
	}
	for _, f := range fields {
		if f.Number == 2 && f.WireType == protobuf.WireBytes {
			return refInnerName(f.Bytes)
		}
	}
	return "", nil
}

func parseNamedField(data []byte) (name string, val CKValue, ok bool, err error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return "", CKValue{}, false, err
	}
	for _, f := range fields {
		switch f.Number {
		case 1:
			nf, err := protobuf.ReadFields(f.Bytes)
			if err != nil {
				return "", CKValue{}, false, err
			}
			for _, n := range nf {
				if n.Number == 1 && n.WireType == protobuf.WireBytes {
					name = string(n.Bytes)
				}
			}
		case 2:
			v, err := parseCKValue(f.Bytes)
			if err != nil {
				return "", CKValue{}, false, err
			}
			val = v
		}
	}
	if name == "" {
		return "", CKValue{}, false, nil
	}
	return name, val, true, nil
}

func parseCKValue(data []byte) (CKValue, error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return CKValue{}, err
	}

	var v CKValue
	for _, f := range fields {
		if f.Number == 1 && f.WireType == protobuf.WireVarint {
			v.Type = int(f.Varint)
		}
	}

	var valueField int
	switch v.Type {
	case 1:
		valueField = 2
	case 3:
		valueField = 7
	case 5:
		valueField = 9
	case 7:
		valueField = 4
	default:
		return v, nil
	}

	for _, f := range fields {
		if f.Number != valueField {
			continue
		}
		if v.Type == 7 {
			if f.WireType == protobuf.WireVarint {
				v.Int = int64(f.Varint)
			}
		} else if f.WireType == protobuf.WireBytes {
			v.Bytes = f.Bytes
		}
	}
	return v, nil
}
