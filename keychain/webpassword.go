package keychain

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/internal/uuid"
	"howett.net/plist"
)

type WebPassword struct {
	Name     string
	Domain   string
	Domains  []string
	Website  bool
	Username string
	Password string
	TOTP     string
	Note     string
	Created  time.Time
	Modified time.Time
}

type entryMeta struct {
	srvr    string
	title   string
	totp    string
	note    string
	domains []string
}

func WebPasswords(items []Item) []WebPassword {
	var manual, website []entryMeta
	for _, it := range items {
		switch it.Agrp {
		case "com.apple.password-manager":
			dict := parsePlist(it.Data)
			m := entryMeta{srvr: it.Srvr, title: asString(dict["title"]), totp: totpURL(dict["totp"]), note: asString(dict["notes"]), domains: siteAssociations(dict["s_as"])}
			if m.title != "" || m.totp != "" || m.note != "" || len(m.domains) > 0 {
				manual = append(manual, m)
			}
		case "com.apple.password-manager.website-metadata":
			if t := asString(parsePlist(it.Data)["wn"]); t != "" {
				website = append(website, entryMeta{srvr: it.Srvr, title: t})
			}
		}
	}

	title := func(srvr string) string {
		for _, m := range manual {
			if m.srvr == srvr {
				return m.title
			}
		}
		for _, w := range website {
			if srvr == w.srvr || strings.HasSuffix(srvr, "."+w.srvr) {
				return w.title
			}
		}
		return ""
	}
	totp := func(srvr string) string {
		for _, m := range manual {
			if m.srvr == srvr {
				return m.totp
			}
		}
		return ""
	}

	note := func(srvr string) string {
		for _, m := range manual {
			if m.srvr == srvr {
				return m.note
			}
		}
		return ""
	}

	associated := func(srvr string) []string {
		for _, m := range manual {
			if m.srvr == srvr {
				return m.domains
			}
		}
		return nil
	}

	var result []WebPassword
	for _, it := range items {
		if it.Class != "inet" || it.Agrp != "com.apple.cfnetwork" {
			continue
		}
		website := !uuid.IsCanonical(it.Srvr)
		wp := WebPassword{
			Name:     title(it.Srvr),
			Domain:   it.Srvr,
			Domains:  allDomains(it.Srvr, website, associated(it.Srvr)),
			Website:  website,
			Username: it.Acct,
			Password: string(it.Data),
			TOTP:     totp(it.Srvr),
			Note:     note(it.Srvr),
		}
		if cdat, ok := it.Attrs["cdat"].(time.Time); ok {
			wp.Created = cdat
		}
		if mdat, ok := it.Attrs["mdat"].(time.Time); ok {
			wp.Modified = mdat
		}
		result = append(result, wp)
	}
	return result
}

func (w WebPassword) IconURL() string {
	d := ""
	switch {
	case w.Website:
		d = w.Domain
	case len(w.Domains) > 0:
		d = w.Domains[0]
	}
	if d == "" {
		return ""
	}
	return "https://icons.duckduckgo.com/ip3/" + d + ".ico"
}

func allDomains(srvr string, website bool, assoc []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if website {
		add(srvr)
	}
	for _, d := range assoc {
		add(d)
	}
	return out
}

func siteAssociations(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		d := cleanDomain(asString(m["s"]))
		if d == "" || strings.HasPrefix(d, "app://") {
			continue
		}
		out = append(out, d)
	}
	return out
}

func cleanDomain(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func parsePlist(data []byte) map[string]any {
	if len(data) == 0 {
		return nil
	}
	var dict map[string]any
	if _, err := plist.Unmarshal(data, &dict); err != nil {
		return nil
	}
	return dict
}

func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	}
	return ""
}

func totpURL(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if s := asString(m["originalURL"]); s != "" {
		return s
	}
	return synthesizeTOTPURL(m)
}

func synthesizeTOTPURL(m map[string]any) string {
	secret, ok := m["secret"].([]byte)
	if !ok || len(secret) == 0 {
		return ""
	}
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))

	switch totpInt(m["algorithm"]) {
	case 1:
		q.Set("algorithm", "SHA256")
	case 2:
		q.Set("algorithm", "SHA512")
	default:
		q.Set("algorithm", "SHA1")
	}
	if d := totpInt(m["digits"]); d > 0 {
		q.Set("digits", fmt.Sprintf("%d", d))
	}
	if p := totpInt(m["period"]); p > 0 {
		q.Set("period", fmt.Sprintf("%d", p))
	}
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/", RawQuery: q.Encode()}
	return u.String()
}

func totpInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	case uint8:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}
