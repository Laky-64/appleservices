package anisette

import (
	"fmt"
	"time"

	"github.com/Laky-64/http"
	"howett.net/plist"
)

const gsaLookupURL = "https://gsa.apple.com/grandslam/GsService2/lookup"

func (c *Client) albertHeaders(s State) map[string]string {
	return map[string]string{
		"X-Mme-Client-Info":     c.clientInfo,
		"User-Agent":            c.userAgent,
		"Content-Type":          "text/x-xml-plist",
		"X-Apple-I-MD-LU":       s.MDLU(),
		"X-Mme-Device-Id":       s.DeviceID(),
		"X-Apple-I-Client-Time": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"X-Apple-I-TimeZone":    "UTC",
		"X-Apple-Locale":        "en_US",
	}
}

func responseDict(body []byte) (map[string]any, error) {
	var doc map[string]any
	if _, err := plist.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("anisette: plist: %w", err)
	}
	resp, ok := doc["Response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("anisette: missing Response")
	}
	return resp, nil
}

func parseSPIM(body []byte) (string, error) {
	resp, err := responseDict(body)
	if err != nil {
		return "", err
	}
	s, _ := resp["spim"].(string)
	if s == "" {
		return "", fmt.Errorf("anisette: missing spim")
	}
	return s, nil
}

func parsePTMTK(body []byte) (ptm, tk string, err error) {
	resp, err := responseDict(body)
	if err != nil {
		return "", "", err
	}
	ptm, _ = resp["ptm"].(string)
	tk, _ = resp["tk"].(string)
	if ptm == "" || tk == "" {
		return "", "", fmt.Errorf("anisette: missing ptm/tk")
	}
	return ptm, tk, nil
}

func lookupProvisioningURLs(hdr map[string]string) (start, finish string, err error) {
	result, err := http.ExecuteRequest(gsaLookupURL, http.Headers(hdr), http.Timeout(30*time.Second), http.Transport(appleRootTransport))
	if result == nil {
		return "", "", err
	}
	var doc map[string]any
	if _, err := plist.Unmarshal(result.Body, &doc); err != nil {
		return "", "", err
	}
	urls, _ := doc["urls"].(map[string]any)
	start, _ = urls["midStartProvisioning"].(string)
	finish, _ = urls["midFinishProvisioning"].(string)
	if start == "" || finish == "" {
		return "", "", fmt.Errorf("anisette: URL bag missing provisioning endpoints")
	}
	return start, finish, nil
}

func albertPost(url string, hdr map[string]string, requestInner string) ([]byte, error) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0"><dict><key>Header</key><dict/><key>Request</key><dict>` +
		requestInner + `</dict></dict></plist>`)
	result, err := http.ExecuteRequest(url,
		http.Method("POST"),
		http.Body(body),
		http.Headers(hdr),
		http.Timeout(30*time.Second),
		http.Transport(appleRootTransport),
	)
	if result != nil && result.StatusCode != 200 {
		return nil, fmt.Errorf("anisette: albert %s status %d", url, result.StatusCode)
	}
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("anisette: albert %s: no response", url)
	}
	return result.Body, nil
}

func startProvisioning(url string, hdr map[string]string) (string, error) {
	body, err := albertPost(url, hdr, "")
	if err != nil {
		return "", err
	}
	return parseSPIM(body)
}

func finishProvisioning(url string, hdr map[string]string, cpimB64 string) (string, string, error) {
	body, err := albertPost(url, hdr, `<key>cpim</key><string>`+cpimB64+`</string>`)
	if err != nil {
		return "", "", err
	}
	return parsePTMTK(body)
}
