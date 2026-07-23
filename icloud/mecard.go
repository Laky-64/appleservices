package icloud

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/internal/httpx"
	"github.com/Laky-64/appleservices/internal/uuid"
	"github.com/Laky-64/http"
	"howett.net/plist"
)

func mmeAuthHeaders(mmeToken, dsid string, anisette map[string]string) map[string]string {
	headers := map[string]string{
		"Authorization":     httpx.BasicAuth(dsid, mmeToken),
		"User-Agent":        httpx.ICloudHelperUA,
		"X-Mme-Client-Info": anisette["X-Mme-Client-Info"],
	}
	httpx.ApplyAnisette(headers, anisette)
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
	return pr.Body, httpx.FirstHeader(pr.Headers, "Content-Type"), nil
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
		if !uuid.IsCanonical(ct.ContactID) {
			return ct.Photo.URL
		}
		if accountFullName != "" && strings.EqualFold(strings.TrimSpace(ct.FirstName+" "+ct.LastName), accountFullName) {
			nameMatch = ct.Photo.URL
		}
	}
	return nameMatch
}

