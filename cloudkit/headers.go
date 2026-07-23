package cloudkit

import (
	"github.com/Laky-64/appleservices/internal/httpx"
	"github.com/Laky-64/appleservices/internal/uuid"
)

type Auth struct {
	DSID            string
	MMEAuthToken    string
	CloudKitToken   string
	AnisetteHeaders map[string]string
	ContainerID     string
	BundleID        string
	Header          CodeInvokeHeader
}

func buildHeaders(auth Auth, userID string) map[string]string {
	h := map[string]string{}
	for k, v := range auth.AnisetteHeaders {
		h[k] = v
	}

	h["Accept"] = "application/json"
	h["X-CloudKit-AuthToken"] = auth.CloudKitToken
	h["X-CloudKit-DSID"] = auth.DSID
	h["X-CloudKit-ContainerId"] = auth.ContainerID
	h["X-CloudKit-BundleId"] = auth.BundleID
	h["X-CloudKit-Environment"] = "production"
	h["X-CloudKit-DatabaseScope"] = "Private"
	h["X-Apple-Request-UUID"] = uuid.New()
	if userID != "" {
		h["X-CloudKit-UserId"] = userID
	}

	h["Authorization"] = httpx.BasicAuth(auth.DSID, auth.MMEAuthToken)
	return h
}
