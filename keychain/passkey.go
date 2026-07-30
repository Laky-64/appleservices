package keychain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode"
)

type Passkey struct {
	RelyingParty string
	Title        string
	UserName     string
	DisplayName  string
	CredentialID []byte
	UserHandle   []byte
	PrivateKey   *ecdsa.PrivateKey
	Created      time.Time
	Modified     time.Time
	IsDeleted    bool
	DeletedAt    time.Time
	Record       DeletedRef
}

func Passkeys(items []Item) []Passkey {
	wn := websiteNames(items)
	var result []Passkey
	for _, it := range items {
		deleted := it.Agrp == "com.apple.webkit.webauthn-recently-deleted"
		if it.Class != "keys" || (it.Agrp != "com.apple.webkit.webauthn" && !deleted) {
			continue
		}
		key, err := parseP256KeyData(it.Data)
		if err != nil {
			continue
		}
		atag := asBytes(it.Attrs["atag"])
		userHandle, userName, displayName := parseAtagCredential(atag)
		pk := Passkey{
			RelyingParty: it.Labl,
			Title:        siteTitle(it.Labl, wn),
			UserName:     userName,
			DisplayName:  displayName,
			CredentialID: asBytes(it.Attrs["alis"]),
			UserHandle:   userHandle,
			PrivateKey:   key,
			IsDeleted:    deleted,
			Record:       DeletedRef{RecordName: it.Name, RecordEtag: it.Etag},
		}
		if cdat, ok := it.Attrs["cdat"].(time.Time); ok {
			pk.Created = cdat
		}
		if mdat, ok := it.Attrs["mdat"].(time.Time); ok {
			pk.Modified = mdat
			if deleted {
				pk.DeletedAt = mdat
			}
		}
		result = append(result, pk)
	}
	return result
}

func websiteNames(items []Item) map[string]string {
	out := map[string]string{}
	for _, it := range items {
		if it.Agrp != "com.apple.password-manager.website-metadata" {
			continue
		}
		if wn := asString(parsePlist(it.Data)["wn"]); wn != "" {
			out[it.Srvr] = wn
		}
	}
	return out
}

func siteTitle(rp string, wn map[string]string) string {
	if rp == "" {
		return ""
	}
	if t := wn[rp]; t != "" {
		return t
	}
	labels := strings.Split(rp, ".")
	label := rp
	if len(labels) >= 2 {
		label = labels[len(labels)-2]
	}
	if label == "" {
		return rp
	}
	r := []rune(label)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func asBytes(v any) []byte {
	b, _ := v.([]byte)
	return b
}

func parseAtagCredential(atag []byte) (userHandle []byte, userName, displayName string) {
	m, ok := decodeCBORStringMap(atag)
	if !ok {
		return atag, "", ""
	}
	return m["id"], string(m["name"]), string(m["displayName"])
}

func decodeCBORStringMap(b []byte) (map[string][]byte, bool) {
	r := cborReader{b: b}
	n, ok := r.mapLen()
	if !ok {
		return nil, false
	}
	out := make(map[string][]byte, n)
	for i := 0; i < n; i++ {
		k, ok := r.strOrBytes()
		if !ok {
			return nil, false
		}
		v, ok := r.strOrBytes()
		if !ok {
			return nil, false
		}
		out[string(k)] = v
	}
	return out, true
}

type cborReader struct {
	b   []byte
	pos int
}

func (r *cborReader) argument() (major byte, arg int, ok bool) {
	if r.pos >= len(r.b) {
		return 0, 0, false
	}
	ib := r.b[r.pos]
	r.pos++
	major = ib >> 5
	ai := ib & 0x1f
	switch {
	case ai < 24:
		return major, int(ai), true
	case ai == 24:
		if r.pos+1 > len(r.b) {
			return 0, 0, false
		}
		arg = int(r.b[r.pos])
		r.pos++
	case ai == 25:
		if r.pos+2 > len(r.b) {
			return 0, 0, false
		}
		arg = int(r.b[r.pos])<<8 | int(r.b[r.pos+1])
		r.pos += 2
	case ai == 26:
		if r.pos+4 > len(r.b) {
			return 0, 0, false
		}
		arg = int(r.b[r.pos])<<24 | int(r.b[r.pos+1])<<16 | int(r.b[r.pos+2])<<8 | int(r.b[r.pos+3])
		r.pos += 4
	default:
		return 0, 0, false
	}
	return major, arg, true
}

func (r *cborReader) mapLen() (int, bool) {
	major, n, ok := r.argument()
	if !ok || major != 5 {
		return 0, false
	}
	return n, true
}

func (r *cborReader) strOrBytes() ([]byte, bool) {
	major, n, ok := r.argument()
	if !ok || (major != 2 && major != 3) || r.pos+n > len(r.b) {
		return nil, false
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v, true
}

func parseP256KeyData(keyData []byte) (*ecdsa.PrivateKey, error) {
	const p256KeyDataLen = 1 + 32*3
	if len(keyData) != p256KeyDataLen || keyData[0] != 0x04 {
		return nil, fmt.Errorf("keychain: unexpected P-256 keyData (len=%d)", len(keyData))
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), keyData[1+32*2:])
}

const (
	FlagUserPresent  = 0x01
	FlagUserVerified = 0x04
)

func (p Passkey) Sign(clientDataHash []byte, flags byte, signCount uint32) (authenticatorData, signature []byte, err error) {
	if p.PrivateKey == nil {
		return nil, nil, fmt.Errorf("keychain: passkey has no private key")
	}
	rpHash := sha256.Sum256([]byte(p.RelyingParty))
	authenticatorData = append(rpHash[:], flags)
	authenticatorData = binary.BigEndian.AppendUint32(authenticatorData, signCount)

	digest := sha256.Sum256(append(append([]byte{}, authenticatorData...), clientDataHash...))
	signature, err = ecdsa.SignASN1(rand.Reader, p.PrivateKey, digest[:])
	if err != nil {
		return nil, nil, fmt.Errorf("keychain: sign assertion: %w", err)
	}
	return authenticatorData, signature, nil
}
