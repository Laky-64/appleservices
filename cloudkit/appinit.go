package cloudkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/Laky-64/appleservices/internal/httpx"
	"github.com/Laky-64/http"
)

var setupBaseURL = "https://setup.icloud.com"

type AppConfig struct {
	DatabaseURL string
	UserID      string
}

func AppInit(auth Auth) (AppConfig, error) {
	endpoint := setupBaseURL + "/setup/ck/v1/ckAppInit?container=" + url.QueryEscape(auth.ContainerID)
	headers := buildHeaders(auth, "")
	result, err := http.ExecuteRequest(endpoint,
		http.Method("POST"),
		http.Headers(headers),
		http.Timeout(30*time.Second),
	)
	if result != nil && result.StatusCode != 200 {
		return AppConfig{}, fmt.Errorf("cloudkit: ckAppInit status %d: body=%q resp-headers: %s", result.StatusCode, snippet(result.Body), respHeaders(result.Headers))
	}
	if err != nil {
		return AppConfig{}, fmt.Errorf("cloudkit: ckAppInit request: %w", err)
	}
	if result == nil {
		return AppConfig{}, fmt.Errorf("cloudkit: ckAppInit: no response")
	}
	var body struct {
		CloudKitDatabaseURL string `json:"cloudKitDatabaseUrl"`
		CloudKitUserID      string `json:"cloudKitUserId"`
	}
	if err := json.Unmarshal(result.Body, &body); err != nil {
		return AppConfig{}, fmt.Errorf("cloudkit: decode ckAppInit response: %w", err)
	}
	if body.CloudKitDatabaseURL != "" {
		return AppConfig{DatabaseURL: body.CloudKitDatabaseURL, UserID: body.CloudKitUserID}, nil
	}
	if part := httpx.FirstHeader(result.Headers, "X-Apple-User-Partition"); part != "" {
		return AppConfig{DatabaseURL: "https://p" + part + "-ckdatabase.icloud.com", UserID: body.CloudKitUserID}, nil
	}
	return AppConfig{}, errors.New("cloudkit: ckAppInit gave neither cloudKitDatabaseUrl nor X-Apple-User-Partition")
}
