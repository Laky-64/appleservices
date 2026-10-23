package escrow

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func parseClubhSections(b []byte, n int) ([][]byte, error) {
	return parseClubhAt(b, 0x1c, 0x2c, n)
}

func parseClubhAt(b []byte, tableOff, dataBase, n int) ([][]byte, error) {
	if tableOff < 0 || dataBase < tableOff || len(b) < dataBase || n < 0 || n > (dataBase-tableOff)/4 {
		return nil, fmt.Errorf("escrow: clubh blob too small (%d)", len(b))
	}
	out := make([][]byte, n)
	for i := range n {
		off := uint64(binary.BigEndian.Uint32(b[tableOff+i*4:]))
		if len(b)-dataBase < 4 || off > uint64(len(b)-dataBase-4) {
			return nil, fmt.Errorf("escrow: clubh section %d offset out of range", i)
		}
		p := dataBase + int(off)
		ln := uint64(binary.BigEndian.Uint32(b[p:]))
		if ln > uint64(len(b)-p-4) {
			return nil, fmt.Errorf("escrow: clubh section %d len out of range", i)
		}
		out[i] = b[p+4 : p+4+int(ln)]
	}
	return out, nil
}

func buildClubhBlob(tag uint32, nonce []byte, sections [][]byte) []byte {
	const tableOff = 0x1c
	const dataBase = 0x2c

	var data bytes.Buffer
	offsets := make([]uint32, len(sections))
	for i, s := range sections {
		offsets[i] = uint32(data.Len())
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		data.Write(l[:])
		data.Write(s)
	}

	b := make([]byte, dataBase+data.Len())
	put := func(o int, v uint32) { binary.BigEndian.PutUint32(b[o:], v) }
	put(0x00, uint32(len(b)))
	put(0x04, tag)
	put(0x08, 0)
	copy(b[0x0c:0x1c], nonce)
	for i, off := range offsets {
		put(tableOff+i*4, off)
	}
	copy(b[dataBase:], data.Bytes())
	return b
}

func buildRecoverBlob(nonce, clubID, M []byte, version uint32) ([]byte, error) {
	if len(nonce) != 16 || len(clubID) == 0 || len(clubID) > 16 || len(M) != 32 {
		return nil, fmt.Errorf("escrow: invalid recover message dimensions")
	}
	b := make([]byte, 0x28+20+4+len(M))
	put := func(o int, v uint32) { binary.BigEndian.PutUint32(b[o:], v) }
	put(0x00, uint32(len(b)))
	put(0x04, 0xa5)
	put(0x08, version)
	copy(b[0x0c:0x1c], nonce)
	put(0x1c, 0)
	put(0x20, 20)
	put(0x24, uint32(len(b)-0x28))
	put(0x28, uint32(len(clubID)))
	copy(b[0x2c:0x3c], clubID)
	put(0x3c, uint32(len(M)))
	copy(b[0x40:], M)
	return b, nil
}
