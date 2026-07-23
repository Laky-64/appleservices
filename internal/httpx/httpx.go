package httpx

import (
	"encoding/base64"
	"strings"
)

const ICloudHelperUA = "com.apple.iCloudHelper/282 CFNetwork/1494.0.7 Darwin/23.4.0"

func Authorization(scheme, user, pass string) string {
	return scheme + " " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func BasicAuth(user, pass string) string { return Authorization("Basic", user, pass) }

func ApplyAnisette(dst, anisette map[string]string) {
	for k, v := range anisette {
		if v == "" {
			continue
		}
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-apple-i-") || lk == "x-mme-device-id" {
			dst[k] = v
		}
	}
}

func FirstHeader(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
