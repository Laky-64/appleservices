package keychain

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (w WebPassword) TOTPCode(t time.Time) (string, error) {
	if w.TOTP == "" {
		return "", fmt.Errorf("keychain: entry %q has no TOTP", w.Name)
	}
	return TOTPCode(w.TOTP, t)
}

func TOTPCode(otpauthURL string, t time.Time) (string, error) {
	u, err := url.Parse(otpauthURL)
	if err != nil {
		return "", fmt.Errorf("keychain: parse otpauth URL: %w", err)
	}
	if u.Scheme != "otpauth" {
		return "", fmt.Errorf("keychain: not an otpauth URL (scheme %q)", u.Scheme)
	}
	q := u.Query()

	secretB32 := strings.ToUpper(strings.TrimSpace(q.Get("secret")))
	if secretB32 == "" {
		return "", fmt.Errorf("keychain: otpauth URL has no secret")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return "", fmt.Errorf("keychain: decode TOTP secret: %w", err)
	}

	digits := 6
	if d := q.Get("digits"); d != "" {
		if n, e := strconv.Atoi(d); e == nil && n > 0 && n <= 9 {
			digits = n
		}
	}
	period := int64(30)
	if p := q.Get("period"); p != "" {
		if n, e := strconv.ParseInt(p, 10, 64); e == nil && n > 0 {
			period = n
		}
	}

	var newHash func() hash.Hash
	switch strings.ToUpper(q.Get("algorithm")) {
	case "", "SHA1":
		newHash = sha1.New
	case "SHA256":
		newHash = sha256.New
	case "SHA512":
		newHash = sha512.New
	default:
		return "", fmt.Errorf("keychain: unsupported TOTP algorithm %q", q.Get("algorithm"))
	}

	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(t.Unix()/period))
	mac := hmac.New(newHash, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod), nil
}
