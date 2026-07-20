package octagon

import (
	"errors"
	"fmt"

	"github.com/Laky-64/appleservices/internal/protobuf"
)

const functionInvokeType = 1101

func FrameCodeInvoke(message []byte) []byte {
	return append(appendUvarint(nil, uint64(len(message))), message...)
}

func UnframeCodeInvoke(body []byte) ([]byte, error) {
	n, off, err := consumeUvarint(body)
	if err != nil {
		return nil, fmt.Errorf("code/invoke framing: %w", err)
	}
	rest := body[off:]
	if uint64(len(rest)) != n {
		return nil, fmt.Errorf("code/invoke framing: prefix length %d != body %d", n, len(rest))
	}
	return rest, nil
}

func appendUvarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func consumeUvarint(b []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		if shift >= 64 {
			return 0, 0, errors.New("varint overflow")
		}
		c := b[i]
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errors.New("truncated varint")
}

func EncodeCodeInvokeRequest(serviceName, functionName, operationUUID string, serializedParameters, header []byte) []byte {
	op := protobuf.NewWriter()
	op.WriteBytes(1, []byte(operationUUID))
	op.WriteVarint(2, functionInvokeType)

	fi := protobuf.NewWriter()
	fi.WriteBytes(1, []byte(serviceName))
	fi.WriteBytes(2, []byte(functionName))
	fi.WriteBytes(3, serializedParameters)

	req := protobuf.NewWriter()
	if header != nil {
		req.WriteBytes(1, header)
	}
	req.WriteBytes(2, op.Bytes())
	req.WriteBytes(functionInvokeType, fi.Bytes())
	return req.Bytes()
}

func DecodeCodeInvokeResponse(responseOperation []byte) ([]byte, error) {
	fields, err := protobuf.ReadFields(responseOperation)
	if err != nil {
		return nil, fmt.Errorf("parsing ResponseOperation: %w", err)
	}
	var fiBytes []byte
	found := false
	for _, f := range fields {
		if f.Number == functionInvokeType && f.WireType == protobuf.WireBytes {
			fiBytes = f.Bytes
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("code/invoke response missing functionInvokeResponse (field %d)", functionInvokeType)
	}
	inner, err := protobuf.ReadFields(fiBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CodeFunctionInvokeResponse: %w", err)
	}
	for _, f := range inner {
		if f.Number == 1 && f.WireType == protobuf.WireBytes {
			return f.Bytes, nil
		}
	}
	return nil, fmt.Errorf("code/invoke response missing serializedResult (field 1)")
}
