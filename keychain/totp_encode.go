package keychain

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func EncodeTOTPField(otpauthURL string) (map[string]any, error) {
	u, err := url.Parse(otpauthURL)
	if err != nil {
		return nil, fmt.Errorf("keychain: parse otpauth url: %w", err)
	}
	if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("keychain: not an otpauth url: %q", otpauthURL)
	}
	q := u.Query()
	secretB32 := strings.ToUpper(strings.TrimSpace(q.Get("secret")))
	if secretB32 == "" {
		return nil, fmt.Errorf("keychain: otpauth url has no secret")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return nil, fmt.Errorf("keychain: decode totp secret: %w", err)
	}

	algorithm := uint64(0)
	switch strings.ToUpper(q.Get("algorithm")) {
	case "SHA256":
		algorithm = 1
	case "SHA512":
		algorithm = 2
	}
	digits := uint64(6)
	if d, err := strconv.Atoi(q.Get("digits")); err == nil && d > 0 {
		digits = uint64(d)
	}
	period := uint64(30)
	if p, err := strconv.Atoi(q.Get("period")); err == nil && p > 0 {
		period = uint64(p)
	}

	issuer := q.Get("issuer")
	label := strings.TrimPrefix(u.Path, "/")
	account := label
	if i := strings.Index(label, ":"); i >= 0 {
		if issuer == "" {
			issuer = strings.TrimSpace(label[:i])
		}
		account = strings.TrimSpace(label[i+1:])
	}

	return map[string]any{
		"secret":       secret,
		"algorithm":    algorithm,
		"digits":       digits,
		"period":       period,
		"accountName":  account,
		"issuer":       issuer,
		"originalURL":  otpauthURL,
		"_initialDate": time.Unix(0, 0).UTC(),
	}, nil
}
