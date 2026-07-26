package icloud

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/http"
)

var devicesBaseURL = "https://gsa.apple.com"

type AccountDevice struct {
	ID                                                    string
	Name                                                  string
	ModelName                                             string
	DeviceClass                                           string
	OS                                                    string
	OSVersion                                             string
	CurrentDevice                                         bool
	ListImageURL, ListImageURL2x, ListImageURL3x          string
	InfoboxImageURL, InfoboxImageURL2x, InfoboxImageURL3x string
}

func IdentityToken(adsid, gsIdmsToken string) string {
	return base64.StdEncoding.EncodeToString([]byte(adsid + ":" + gsIdmsToken))
}

type deviceJSON struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	ModelName              string `json:"modelName"`
	DeviceClass            string `json:"deviceClass"`
	OS                     string `json:"os"`
	OSVersion              string `json:"osVersion"`
	CurrentDevice          bool   `json:"currentDevice"`
	ListImageLocation      string `json:"listImageLocation"`
	ListImageLocation2x    string `json:"listImageLocation2x"`
	ListImageLocation3x    string `json:"listImageLocation3x"`
	InfoboxImageLocation   string `json:"infoboxImageLocation"`
	InfoboxImageLocation2x string `json:"infoboxImageLocation2x"`
	InfoboxImageLocation3x string `json:"infoboxImageLocation3x"`
}

type devicesSummaryJSON struct {
	ManageDevices struct {
		Devices []deviceJSON `json:"devices"`
	} `json:"manageDevices"`
}

func parseDevicesSummary(body []byte) ([]AccountDevice, error) {
	var resp devicesSummaryJSON
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("icloud: decode devices summary: %w", err)
	}
	out := make([]AccountDevice, 0, len(resp.ManageDevices.Devices))
	for _, d := range resp.ManageDevices.Devices {
		out = append(out, AccountDevice{
			ID:                d.ID,
			Name:              d.Name,
			ModelName:         d.ModelName,
			DeviceClass:       d.DeviceClass,
			OS:                d.OS,
			OSVersion:         d.OSVersion,
			CurrentDevice:     d.CurrentDevice,
			ListImageURL:      d.ListImageLocation,
			ListImageURL2x:    d.ListImageLocation2x,
			ListImageURL3x:    d.ListImageLocation3x,
			InfoboxImageURL:   d.InfoboxImageLocation,
			InfoboxImageURL2x: d.InfoboxImageLocation2x,
			InfoboxImageURL3x: d.InfoboxImageLocation3x,
		})
	}
	return out, nil
}

func anisetteGet(anisette map[string]string, name string) string {
	for k, v := range anisette {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func FetchDevices(anisetteHeaders map[string]string, identityToken string) ([]AccountDevice, error) {
	ck := make([]byte, 16)
	_, _ = rand.Read(ck)
	headers := map[string]string{
		"Accept":                 "application/json",
		"Accept-Language":        "en",
		"X-Apple-Identity-Token": identityToken,
		"X-Apple-I-CK":           hex.EncodeToString(ck),
		"X-Mme-Client-Info":      anisetteGet(anisetteHeaders, "X-Mme-Client-Info"),
	}
	for _, k := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-Mme-Legacy-Device-Id", "X-Mme-Country"} {
		if v := anisetteGet(anisetteHeaders, k); v != "" {
			headers[k] = v
		}
	}

	result, err := http.ExecuteRequest(devicesBaseURL+"/appleid/account/manage/security/devices/summary",
		http.Method("GET"),
		http.Headers(headers),
		http.Transport(gsa.AppleRootTransport()),
		http.Timeout(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("icloud: devices summary request: %w", err)
	}
	if result.StatusCode != 200 {
		return nil, fmt.Errorf("icloud: devices summary status %d", result.StatusCode)
	}
	return parseDevicesSummary(result.Body)
}
