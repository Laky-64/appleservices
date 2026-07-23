package icloud

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Laky-64/appleservices/internal/httpx"
	"github.com/Laky-64/appleservices/internal/uuid"
	"github.com/Laky-64/http"
	"howett.net/plist"
)

var setupBaseURL = "https://setup.icloud.com"

type DelegateTokens struct {
	DSID          string
	MMEAuthToken  string
	CloudKitToken string
	ServiceData   map[string]any
}

func FetchDelegateTokens(anisetteHeaders map[string]string, username, adsid, pet string) (DelegateTokens, error) {
	body := map[string]any{
		"apple-id":  username,
		"delegates": map[string]any{"com.apple.mobileme": map[string]any{}},
		"password":  pet,
		"client-id": uuid.New(),
	}
	var buf bytes.Buffer
	if err := plist.NewEncoder(&buf).Encode(body); err != nil {
		return DelegateTokens{}, fmt.Errorf("icloud: encode loginDelegates body: %w", err)
	}

	headers := map[string]string{
		"Content-Type":      "text/plist",
		"X-Apple-ADSID":     adsid,
		"User-Agent":        "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
		"X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
		"Authorization":     httpx.BasicAuth(username, pet),
	}
	for k, v := range anisetteHeaders {
		headers[k] = v
	}

	result, err := http.ExecuteRequest(setupBaseURL+"/setup/iosbuddy/loginDelegates",
		http.Method("POST"),
		http.Body(buf.Bytes()),
		http.Headers(headers),
		http.Timeout(30*time.Second),
	)
	if err != nil {
		return DelegateTokens{}, fmt.Errorf("icloud: loginDelegates request: %w", err)
	}
	if result.StatusCode != 200 {
		return DelegateTokens{}, fmt.Errorf("icloud: loginDelegates status %d", result.StatusCode)
	}

	var decoded map[string]any
	if _, err := plist.Unmarshal(result.Body, &decoded); err != nil {
		return DelegateTokens{}, fmt.Errorf("icloud: decode loginDelegates response: %w", err)
	}
	return extractDelegateTokens(decoded, adsid)
}

func extractDelegateTokens(resp map[string]any, fallbackDSID string) (DelegateTokens, error) {
	delegates, ok := resp["delegates"].(map[string]any)
	if !ok {
		return DelegateTokens{}, errors.New("icloud: loginDelegates response has no delegates")
	}
	mme, ok := delegates["com.apple.mobileme"].(map[string]any)
	if !ok {
		return DelegateTokens{}, errors.New("icloud: loginDelegates response has no com.apple.mobileme delegate")
	}
	sd, ok := mme["service-data"].(map[string]any)
	if !ok {
		msg, _ := mme["status-message"].(string)
		return DelegateTokens{}, fmt.Errorf("icloud: mobileme delegate has no service-data (status-message: %q)", msg)
	}
	tokens, ok := sd["tokens"].(map[string]any)
	if !ok {
		return DelegateTokens{}, errors.New("icloud: mobileme service-data has no tokens")
	}
	mmeToken, ok := tokens["mmeAuthToken"].(string)
	if !ok || mmeToken == "" {
		msg, _ := mme["status-message"].(string)
		return DelegateTokens{}, fmt.Errorf("icloud: no mmeAuthToken in response (status-message: %q)", msg)
	}
	ckToken, _ := tokens["cloudKitToken"].(string)

	dsid := fallbackDSID
	if d := coerceDSID(resp["dsid"]); d != "" {
		dsid = d
	} else if d := coerceDSID(sd["dsid"]); d != "" {
		dsid = d
	}
	return DelegateTokens{DSID: dsid, MMEAuthToken: mmeToken, CloudKitToken: ckToken, ServiceData: sd}, nil
}

func coerceDSID(v any) string {
	switch d := v.(type) {
	case string:
		return d
	case uint64:
		return strconv.FormatUint(d, 10)
	case int64:
		return strconv.FormatInt(d, 10)
	}
	return ""
}
