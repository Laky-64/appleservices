package keychain

import (
	"strings"
	"time"

	"howett.net/plist"
)

type WebPassword struct {
	Name     string
	Domain   string
	Website  bool
	Username string
	Password string
	TOTP     string
	Created  time.Time
	Modified time.Time
}

type entryMeta struct {
	srvr  string
	title string
	totp  string
}

func WebPasswords(items []Item) []WebPassword {
	var manual, website []entryMeta
	for _, it := range items {
		switch it.Agrp {
		case "com.apple.password-manager":
			dict := parsePlist(it.Data)
			m := entryMeta{srvr: it.Srvr, title: asString(dict["title"]), totp: totpURL(dict["totp"])}
			if m.title != "" || m.totp != "" {
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

	var result []WebPassword
	for _, it := range items {
		if it.Class != "inet" || it.Agrp != "com.apple.cfnetwork" {
			continue
		}
		wp := WebPassword{
			Name:     title(it.Srvr),
			Domain:   it.Srvr,
			Website:  !isUUID(it.Srvr),
			Username: it.Acct,
			Password: string(it.Data),
			TOTP:     totp(it.Srvr),
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
	return asString(m["originalURL"])
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
