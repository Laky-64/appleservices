package escrow

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Laky-64/http"
	"howett.net/plist"

	"github.com/Laky-64/appleservices/internal/srp"
)

var setupBaseURL = "https://setup.icloud.com"

const (
	escrowVersion = "1"
	recordLabel   = "com.apple.securebackup.record"
	petAuthScheme = "Basic"
)

type Client struct {
	escrowURL string
	anisette  map[string]string
}

func NewClient(escrowURL string, anisette map[string]string) *Client {
	return &Client{escrowURL: strings.TrimSuffix(escrowURL, ":443"), anisette: anisette}
}

func (c *Client) Recover(appleID, accountPassword, pet, dsid, passcode, bottleID, escrowLabel string) ([]byte, error) {
	recBody := plistBody(
		`<key>version</key><integer>` + escrowVersion + `</integer>` +
			`<key>command</key><string>GETRECORDS</string>` +
			`<key>label</key><string>` + recordLabel + `</string>`)
	rb, status, err := c.escrowPost("get_records", "Basic", appleID, accountPassword, recBody)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("escrow: get_records status %d (errorCode=%s)", status, escrowErrCode(rb))
	}
	label, err := selectRecordLabel(rb, bottleID, escrowLabel)
	if err != nil {
		return nil, err
	}

	params := srp.NewParams()
	N, g := params.N, params.G
	const nWidth = 256
	aRaw := make([]byte, 32)
	if _, err := rand.Read(aRaw); err != nil {
		return nil, err
	}
	aInt := new(big.Int).SetBytes(aRaw)
	A := new(big.Int).Exp(g, aInt, N)
	aBytes := leftPad(A.Bytes(), nWidth)

	initBody := plistBody(
		`<key>version</key><integer>` + escrowVersion + `</integer>` +
			`<key>command</key><string>SRP_INIT</string>` +
			`<key>label</key><string>` + label + `</string>` +
			`<key>blob</key><string>` + base64.StdEncoding.EncodeToString(aBytes) + `</string>`)
	sb, sstatus, err := c.escrowPost("srp_init", petAuthScheme, appleID, pet, initBody)
	if err != nil {
		return nil, err
	}
	if sstatus != 200 {
		return nil, fmt.Errorf("escrow: srp_init status %d (errorCode=%s)", sstatus, escrowErrCode(sb))
	}
	var initDoc map[string]any
	if _, err := plist.Unmarshal(sb, &initDoc); err != nil {
		return nil, fmt.Errorf("escrow: decode srp_init: %w", err)
	}
	initRespB64, _ := initDoc["respBlob"].(string)
	respBlob, err := base64.StdEncoding.DecodeString(initRespB64)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode srp_init respBlob: %w", err)
	}
	secs, err := parseClubhSections(respBlob, 3)
	if err != nil {
		return nil, fmt.Errorf("escrow: parse srp_init resp sections: %w", err)
	}
	if len(respBlob) < 0x1c {
		return nil, errors.New("escrow: srp_init respBlob too short for nonce")
	}
	clubID, salt, B := secs[0], secs[1], new(big.Int).SetBytes(secs[2])
	nonce := respBlob[0x0c:0x1c]

	M, Kses := computeEscrowM(N, g, aInt, A, B, salt, dsid, passcode)
	recoverBlob := buildRecoverBlob(nonce, clubID, M)

	recoverBody := plistBody(
		`<key>version</key><integer>` + escrowVersion + `</integer>` +
			`<key>command</key><string>RECOVER</string>` +
			`<key>label</key><string>` + label + `</string>` +
			`<key>blob</key><string>` + base64.StdEncoding.EncodeToString(recoverBlob) + `</string>`)
	rr, rstatus, err := c.escrowPost("recover", petAuthScheme, appleID, pet, recoverBody)
	if err != nil {
		return nil, err
	}
	if rstatus != 200 {
		return nil, fmt.Errorf("escrow: recover status %d (errorCode=%s)", rstatus, escrowErrCode(rr))
	}
	var recDoc map[string]any
	if _, err := plist.Unmarshal(rr, &recDoc); err != nil {
		return nil, fmt.Errorf("escrow: decode recover resp: %w", err)
	}
	recRespB64, _ := recDoc["respBlob"].(string)
	recResp, err := base64.StdEncoding.DecodeString(recRespB64)
	if err != nil {
		return nil, fmt.Errorf("escrow: decode recover respBlob: %w", err)
	}

	return decodeRecoverPayload(recResp, Kses, passcode)
}

func decodeRecoverPayload(recResp, sessionKey []byte, passcode string) ([]byte, error) {
	rsecs, err := parseClubhSections(recResp, 3)
	if err != nil {
		return nil, fmt.Errorf("escrow: parse recover resp sections: %w", err)
	}
	iv1, ct1 := rsecs[1], rsecs[2]
	record, err := aesCBCDecrypt(sessionKey, iv1, ct1)
	if err != nil {
		return nil, fmt.Errorf("escrow: layer-1 decrypt: %w", err)
	}
	if len(record) < 0x30 {
		return nil, errors.New("escrow: layer-1 record too short")
	}
	kekIters := int(binary.BigEndian.Uint32(record[0x0c:]))
	recSecs, err := parseClubhAt(record, 0x14, 0x30, 6)
	if err != nil {
		return nil, fmt.Errorf("escrow: parse record: %w", err)
	}
	salt2, encResp := recSecs[1], recSecs[3]
	if len(salt2) < 16 {
		return nil, errors.New("escrow: record salt too short")
	}
	kek := deriveKEK([]byte(passcode), salt2, kekIters, 16)
	secret, err := aesCBCDecrypt(kek, salt2[:16], encResp)
	if err != nil {
		return nil, fmt.Errorf("escrow: layer-2 decrypt: %w", err)
	}
	if len(secret) == 0 {
		return nil, errors.New("escrow: layer-2 decrypt produced empty secret")
	}
	if n := int(secret[len(secret)-1]); n >= 1 && n <= 16 && n <= len(secret) {
		secret = secret[:len(secret)-n]
	}
	var sdoc map[string]any
	if _, err := plist.Unmarshal(secret, &sdoc); err != nil {
		return nil, fmt.Errorf("escrow: decode SecureBackup secret bplist: %w", err)
	}
	ent, ok := sdoc["BottledPeerEntropy"].([]byte)
	if !ok {
		return nil, errors.New("escrow: no BottledPeerEntropy in recovered secret")
	}
	return ent, nil
}

func selectRecordLabel(rb []byte, bottleID, escrowLabel string) (string, error) {
	var doc map[string]any
	if _, err := plist.Unmarshal(rb, &doc); err != nil {
		return "", fmt.Errorf("escrow: decode get_records: %w", err)
	}
	list, _ := doc["metadataList"].([]any)
	var icdp []string
	for _, e := range list {
		rec, _ := e.(map[string]any)
		label, _ := rec["label"].(string)
		if !strings.HasPrefix(label, "com.apple.icdp.record.") {
			continue
		}
		icdp = append(icdp, label)
		if escrowLabel != "" && label == escrowLabel {
			return label, nil
		}
		if bottleID != "" && recordMatchesBottle(rec, bottleID) {
			return label, nil
		}
	}
	if len(icdp) == 1 {

		return icdp[0], nil
	}
	if len(icdp) == 0 {
		return "", errors.New("escrow: no com.apple.icdp.record.* record in get_records")
	}
	if bottleID == "" && escrowLabel == "" {
		return icdp[0], nil
	}
	return "", fmt.Errorf("escrow: no icdp record matched bottleID/label among %d records", len(icdp))
}

func recordMatchesBottle(rec map[string]any, bottleID string) bool {
	metaB64, _ := rec["metadata"].(string)
	if metaB64 == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(metaB64)
	if err != nil {
		return false
	}
	var meta map[string]any
	if _, err := plist.Unmarshal(raw, &meta); err != nil {
		return false
	}
	id, _ := meta["bottleID"].(string)
	return id != "" && id == bottleID
}

func (c *Client) escrowPost(endpoint, scheme, user, pass string, body []byte) ([]byte, int, error) {
	headers := map[string]string{
		"Authorization":     scheme + " " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)),
		"Content-Type":      "application/x-apple-plist",
		"Accept":            "*/*",
		"User-Agent":        "com.apple.cloudservices 1.0",
		"X-Mme-Client-Info": c.anisette["X-Mme-Client-Info"],
	}
	for k, v := range c.anisette {
		if v == "" {
			continue
		}
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-apple-i-") || lk == "x-mme-device-id" {
			headers[k] = v
		}
	}
	result, err := http.ExecuteRequest(c.escrowURL+"/escrowproxy/api/"+endpoint,
		http.Method("POST"),
		http.Body(body),
		http.Headers(headers),
		http.Timeout(30*time.Second),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("escrow: %s request: %w", endpoint, err)
	}
	return result.Body, result.StatusCode, nil
}

func DiscoverURL(mmeToken, dsid string, anisette map[string]string) (string, error) {
	headers := map[string]string{
		"Authorization":     "Basic " + base64.StdEncoding.EncodeToString([]byte(dsid+":"+mmeToken)),
		"Accept":            "*/*",
		"User-Agent":        "com.apple.iCloudHelper/282 CFNetwork/1494.0.7 Darwin/23.4.0",
		"X-Mme-Client-Info": anisette["X-Mme-Client-Info"],
	}
	for k, v := range anisette {
		if v == "" {
			continue
		}
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-apple-i-") || lk == "x-mme-device-id" {
			headers[k] = v
		}
	}
	result, err := http.ExecuteRequest(setupBaseURL+"/setup/get_account_settings",
		http.Method("GET"),
		http.Headers(headers),
		http.Timeout(30*time.Second),
	)
	if err != nil {
		return "", fmt.Errorf("escrow: get_account_settings request: %w", err)
	}
	if result.StatusCode != 200 {
		return "", fmt.Errorf("escrow: get_account_settings status %d", result.StatusCode)
	}
	var doc map[string]any
	if _, err := plist.Unmarshal(result.Body, &doc); err != nil {
		return "", fmt.Errorf("escrow: decode account settings: %w", err)
	}
	var escrowURL string
	walkStrings(doc, "", func(path, val string) {
		if strings.HasSuffix(strings.ToLower(path), "escrowproxyurl") {
			escrowURL = val
		}
	})
	if escrowURL == "" {
		return "", errors.New("escrow: no escrowProxyUrl in account settings")
	}
	return strings.TrimSuffix(escrowURL, ":443"), nil
}

func walkStrings(o any, path string, visit func(path, val string)) {
	switch v := o.(type) {
	case map[string]any:
		for k, val := range v {
			walkStrings(val, path+"/"+k, visit)
		}
	case []any:
		for i, val := range v {
			walkStrings(val, fmt.Sprintf("%s[%d]", path, i), visit)
		}
	case string:
		visit(path, v)
	}
}

func plistBody(innerXML string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` +
		`<plist version="1.0"><dict>` + innerXML + `</dict></plist>`)
}

func escrowErrCode(body []byte) string {
	var doc map[string]any
	if _, err := plist.Unmarshal(body, &doc); err != nil {
		return "?"
	}
	if ec, ok := doc["errorCode"]; ok {
		return fmt.Sprintf("%v", ec)
	}
	return ""
}
