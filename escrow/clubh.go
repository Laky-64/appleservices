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
	if len(b) < dataBase {
		return nil, fmt.Errorf("escrow: clubh blob too small (%d)", len(b))
	}
	be := func(o int) int { return int(binary.BigEndian.Uint32(b[o:])) }
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		off := be(tableOff + i*4)
		p := dataBase + off
		if p+4 > len(b) {
			return nil, fmt.Errorf("escrow: clubh section %d offset out of range", i)
		}
		ln := be(p)
		if p+4+ln > len(b) {
			return nil, fmt.Errorf("escrow: clubh section %d len out of range", i)
		}
		out[i] = b[p+4 : p+4+ln]
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

func buildRecoverBlob(nonce, clubID, M []byte) []byte {
	var data bytes.Buffer
	putSec := func(s []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		data.Write(l[:])
		data.Write(s)
	}
	off0 := 0
	putSec(clubID)
	off1 := data.Len()
	putSec(M)
	off2 := data.Len()

	b := make([]byte, 0x28+data.Len())
	put := func(o int, v uint32) { binary.BigEndian.PutUint32(b[o:], v) }
	put(0x00, uint32(len(b)))
	put(0x04, 0xa5)
	put(0x08, 0)
	copy(b[0x0c:0x1c], nonce)
	put(0x1c, uint32(off0))
	put(0x20, uint32(off1))
	put(0x24, uint32(off2))
	copy(b[0x28:], data.Bytes())
	return b
}
