package icloud

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Laky-64/http"
	"howett.net/plist"
)

func mmeAuthHeaders(mmeToken, dsid string, anisette map[string]string) map[string]string {
	headers := map[string]string{
		"Authorization":     "Basic " + base64.StdEncoding.EncodeToString([]byte(dsid+":"+mmeToken)),
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
	return headers
}

func FetchAccountBag(mmeToken, dsid string, anisette map[string]string) (map[string]any, error) {
	headers := mmeAuthHeaders(mmeToken, dsid, anisette)
	headers["Accept"] = "*/*"

	result, err := http.ExecuteRequest(setupBaseURL+"/setup/get_account_settings",
		http.Method("GET"),
		http.Headers(headers),
		http.Timeout(30*time.Second),
	)
	if result != nil && result.StatusCode != 200 {
		return nil, fmt.Errorf("icloud: get_account_settings status %d", result.StatusCode)
	}
	if err != nil {
		return nil, fmt.Errorf("icloud: get_account_settings request: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("icloud: get_account_settings: no response")
	}
	var bag map[string]any
	if _, err := plist.Unmarshal(result.Body, &bag); err != nil {
		return nil, fmt.Errorf("icloud: decode account bag: %w", err)
	}
	return bag, nil
}

func ContactsDAVURL(bag map[string]any) string {
	mme, _ := bag["com.apple.mobileme"].(map[string]any)
	c, _ := mme["com.apple.Dataclass.Contacts"].(map[string]any)
	url, _ := c["url"].(string)
	return url
}

func AccountFullName(bag map[string]any) string {
	info, _ := bag["appleAccountInfo"].(map[string]any)
	if n, _ := info["fullName"].(string); n != "" {
		return n
	}
	first, _ := info["firstName"].(string)
	last, _ := info["lastName"].(string)
	return strings.TrimSpace(first + " " + last)
}

type addressBook struct {
	MeCardID string `json:"meCardId"`
	Contacts []struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		ContactID string `json:"contactId"`
		Photo     *struct {
			URL string `json:"url"`
		} `json:"photo"`
	} `json:"contacts"`
}

func ProfilePhoto(contactsDAVURL, accountFullName, mmeToken, dsid string, anisette map[string]string) ([]byte, string, error) {
	if contactsDAVURL == "" {
		return nil, "", fmt.Errorf("icloud: no Contacts service URL in account bag")
	}
	wsBase := strings.Replace(strings.TrimSuffix(contactsDAVURL, ":443"), "-contacts.", "-contactsws.", 1)
	headers := mmeAuthHeaders(mmeToken, dsid, anisette)
	headers["Accept"] = "application/json, text/json, */*"

	result, err := http.ExecuteRequest(wsBase+"/c2/addressbook/?order=last,first&locale=en_US",
		http.Method("GET"), http.Headers(headers), http.Timeout(30*time.Second))
	if result != nil && result.StatusCode != 200 {
		return nil, "", fmt.Errorf("icloud: addressbook status %d", result.StatusCode)
	}
	if err != nil {
		return nil, "", fmt.Errorf("icloud: addressbook request: %w", err)
	}
	if result == nil {
		return nil, "", fmt.Errorf("icloud: addressbook: no response")
	}
	var ab addressBook
	if err := json.Unmarshal(result.Body, &ab); err != nil {
		return nil, "", fmt.Errorf("icloud: decode addressbook: %w", err)
	}

	photoURL := meCardPhotoURL(ab, accountFullName)
	if photoURL == "" {
		return nil, "", nil
	}

	pr, err := http.ExecuteRequest(photoURL, http.Method("GET"), http.Headers(headers), http.Timeout(30*time.Second))
	if pr != nil && pr.StatusCode != 200 {
		return nil, "", fmt.Errorf("icloud: me-card photo status %d", pr.StatusCode)
	}
	if err != nil {
		return nil, "", fmt.Errorf("icloud: me-card photo request: %w", err)
	}
	if pr == nil || len(pr.Body) == 0 {
		return nil, "", fmt.Errorf("icloud: me-card photo: empty response")
	}
	return pr.Body, firstHeader(pr.Headers, "Content-Type"), nil
}

func meCardPhotoURL(ab addressBook, accountFullName string) string {
	var nameMatch string
	for _, ct := range ab.Contacts {
		if ct.Photo == nil || ct.Photo.URL == "" {
			continue
		}
		if ct.ContactID == ab.MeCardID && ab.MeCardID != "" {
			return ct.Photo.URL
		}
		if !isPlainUUID(ct.ContactID) {
			return ct.Photo.URL
		}
		if accountFullName != "" && strings.EqualFold(strings.TrimSpace(ct.FirstName+" "+ct.LastName), accountFullName) {
			nameMatch = ct.Photo.URL
		}
	}
	return nameMatch
}

func isPlainUUID(s string) bool {
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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func firstHeader(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
