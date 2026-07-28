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
	Name      string
	Domain    string
	Domains   []string
	Website   bool
	Username  string
	Password  string
	TOTP      string
	Note      string
	Created   time.Time
	Modified  time.Time
	IsDeleted bool
	DeletedAt time.Time
	Deleted   []DeletedRef
}

type DeletedRef struct {
	RecordName string
	RecordEtag string
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
	result = append(result, deletedWebPasswords(items, title)...)
	return result
}

func deletedWebPasswords(items []Item, resolveTitle func(srvr string) string) []WebPassword {
	key := func(srvr, acct string) string { return srvr + "\x00" + acct }

	type companion struct {
		title, note string
		ref         DeletedRef
	}
	companions := map[string]companion{}
	for _, it := range items {
		if it.Agrp != "com.apple.password-manager-recently-deleted" {
			continue
		}
		d := parsePlist(it.Data)
		companions[key(it.Srvr, it.Acct)] = companion{
			title: firstNonEmpty(asString(d["title"]), sHiTitle(d["s_hi"])),
			note:  asString(d["notes"]),
			ref:   DeletedRef{RecordName: it.Name, RecordEtag: it.Etag},
		}
	}

	seen := map[string]bool{}
	var out []WebPassword

	for _, it := range items {
		if it.Class != "inet" || it.Agrp != "com.apple.cfnetwork-recently-deleted" {
			continue
		}
		k := key(it.Srvr, it.Acct)
		c := companions[k]
		title := c.title
		if title == "" {
			title = resolveTitle(it.Srvr)
		}
		refs := []DeletedRef{{RecordName: it.Name, RecordEtag: it.Etag}}
		if c.ref.RecordName != "" {
			refs = append(refs, c.ref)
		}
		wp := WebPassword{
			Name:      title,
			Domain:    it.Srvr,
			Website:   !uuid.IsCanonical(it.Srvr),
			Username:  it.Acct,
			Password:  string(it.Data),
			Note:      c.note,
			IsDeleted: true,
			Deleted:   refs,
		}
		if mdat, ok := it.Attrs["mdat"].(time.Time); ok {
			wp.DeletedAt = mdat
		}
		out = append(out, wp)
		seen[k] = true
	}

	for _, it := range items {
		if it.Class != "inet" || it.Agrp != "com.apple.password-manager.personal-recently-deleted" {
			continue
		}
		k := key(it.Srvr, it.Acct)
		if seen[k] {
			continue
		}
		pw, title := deletedSecretAndTitle(parsePlist(it.Data)["s_hi"])
		if title == "" {
			title = resolveTitle(it.Srvr)
		}
		wp := WebPassword{
			Name:      title,
			Domain:    it.Srvr,
			Website:   !uuid.IsCanonical(it.Srvr),
			Username:  it.Acct,
			Password:  pw,
			IsDeleted: true,
			Deleted:   []DeletedRef{{RecordName: it.Name, RecordEtag: it.Etag}},
		}
		if mdat, ok := it.Attrs["mdat"].(time.Time); ok {
			wp.DeletedAt = mdat
		}
		out = append(out, wp)
		seen[k] = true
	}
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func sHiTitle(v any) string {
	_, title := deletedSecretAndTitle(v)
	return title
}

func deletedSecretAndTitle(v any) (password, title string) {
	arr, ok := v.([]any)
	if !ok {
		return "", ""
	}
	for _, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		switch asString(m["t"]) {
		case "pwcr":
			if p := asString(m["p"]); p != "" {
				password = p
			}
		case "pwshgr":
			if g := asString(m["gn"]); g != "" {
				title = g
			}
		}
	}
	return password, title
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
