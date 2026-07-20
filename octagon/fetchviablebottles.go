package octagon

import (
	"fmt"

	"github.com/Laky-64/appleservices/internal/protobuf"
)

type Invoker interface {
	Invoke(functionName string, serializedParameters []byte) ([]byte, error)
}

func MarshalFetchViableBottlesRequest() []byte {
	return protobuf.NewWriter().Bytes()
}

type ViableBottles struct {
	Viable  []Bottle
	Partial []Bottle
}

type Bottle struct {
	Contents                []byte
	EscrowedSigningSPKI     []byte
	SignatureUsingEscrowKey []byte
	SignatureUsingPeerKey   []byte
	PeerID                  string
	BottleID                string
}

func MarshalBottle(v Bottle) []byte {
	w := protobuf.NewWriter()
	w.WriteBytes(2, v.Contents)
	w.WriteBytes(3, v.EscrowedSigningSPKI)
	w.WriteBytes(4, v.SignatureUsingEscrowKey)
	w.WriteBytes(5, v.SignatureUsingPeerKey)
	w.WriteBytes(6, []byte(v.PeerID))
	w.WriteBytes(7, []byte(v.BottleID))
	return w.Bytes()
}

func UnmarshalBottle(data []byte) (Bottle, error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return Bottle{}, err
	}
	var b Bottle
	for _, f := range fields {
		switch f.Number {
		case 2:
			b.Contents = f.Bytes
		case 3:
			b.EscrowedSigningSPKI = f.Bytes
		case 4:
			b.SignatureUsingEscrowKey = f.Bytes
		case 5:
			b.SignatureUsingPeerKey = f.Bytes
		case 6:
			b.PeerID = string(f.Bytes)
		case 7:
			b.BottleID = string(f.Bytes)
		}
	}
	return b, nil
}

func FetchViableBottles(inv Invoker) (ViableBottles, error) {
	result, err := inv.Invoke("fetchViableBottles", MarshalFetchViableBottlesRequest())
	if err != nil {
		return ViableBottles{}, err
	}
	return UnmarshalViableBottlesResponse(result)
}

func UnmarshalViableBottlesResponse(data []byte) (ViableBottles, error) {
	fields, err := protobuf.ReadFields(data)
	if err != nil {
		return ViableBottles{}, fmt.Errorf("octagon: decode FetchViableBottlesResponse: %w", err)
	}
	var vb ViableBottles
	for _, f := range fields {
		if f.WireType != protobuf.WireBytes {
			continue
		}
		switch f.Number {
		case 1:
			b, err := UnmarshalBottle(f.Bytes)
			if err != nil {
				return ViableBottles{}, err
			}
			vb.Viable = append(vb.Viable, b)
		case 2:
			b, err := UnmarshalBottle(f.Bytes)
			if err != nil {
				return ViableBottles{}, err
			}
			vb.Partial = append(vb.Partial, b)
		}
	}
	return vb, nil
}
