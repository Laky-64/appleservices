package protobuf

import "fmt"

type Writer struct {
	buf []byte
}

func NewWriter() *Writer {
	return &Writer{}
}

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func tag(fieldNumber int, wireType WireType) uint64 {
	return uint64(fieldNumber)<<3 | uint64(wireType)
}

func (w *Writer) WriteVarint(fieldNumber int, v uint64) {
	w.buf = appendVarint(w.buf, tag(fieldNumber, WireVarint))
	w.buf = appendVarint(w.buf, v)
}

func (w *Writer) WriteBytes(fieldNumber int, data []byte) {
	w.buf = appendVarint(w.buf, tag(fieldNumber, WireBytes))
	w.buf = appendVarint(w.buf, uint64(len(data)))
	w.buf = append(w.buf, data...)
}

func (w *Writer) Bytes() []byte {
	return w.buf
}

type WireType int

const (
	WireVarint WireType = 0
	WireBytes  WireType = 2
)

type Field struct {
	Number   int
	WireType WireType
	Varint   uint64
	Bytes    []byte
}

func readVarint(data []byte, pos int) (value uint64, newPos int, err error) {
	var shift uint
	for {
		if shift >= 64 {
			return 0, 0, fmt.Errorf("varint at offset %d exceeds 10 bytes (64 bits)", pos)
		}
		if pos >= len(data) {
			return 0, 0, fmt.Errorf("truncated varint at offset %d", pos)
		}
		b := data[pos]
		pos++
		value |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return value, pos, nil
		}
		shift += 7
	}
}

func ReadFields(data []byte) ([]Field, error) {
	var fields []Field
	pos := 0

	for pos < len(data) {
		tagValue, newPos, err := readVarint(data, pos)
		if err != nil {
			return nil, fmt.Errorf("reading tag: %w", err)
		}
		pos = newPos

		fieldNumber := int(tagValue >> 3)
		wireType := WireType(tagValue & 0x7)

		switch wireType {
		case WireVarint:
			v, newPos, err := readVarint(data, pos)
			if err != nil {
				return nil, fmt.Errorf("reading varint value for field %d: %w", fieldNumber, err)
			}
			pos = newPos
			fields = append(fields, Field{Number: fieldNumber, WireType: WireVarint, Varint: v})

		case WireBytes:
			length, newPos, err := readVarint(data, pos)
			if err != nil {
				return nil, fmt.Errorf("reading length for field %d: %w", fieldNumber, err)
			}
			pos = newPos
			if length > uint64(len(data)-pos) {
				return nil, fmt.Errorf("field %d declares length %d exceeding remaining %d bytes", fieldNumber, length, len(data)-pos)
			}
			fields = append(fields, Field{Number: fieldNumber, WireType: WireBytes, Bytes: data[pos : pos+int(length)]})
			pos += int(length)

		default:
			return nil, fmt.Errorf("field %d has unsupported wire type %d", fieldNumber, wireType)
		}
	}

	return fields, nil
}
