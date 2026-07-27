package cloudkit

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Laky-64/http"
	"github.com/Laky-64/http/types"

	"github.com/Laky-64/appleservices/internal/uuid"
	"github.com/Laky-64/appleservices/octagon"
)

const statusUnauthorized = 401

type Client struct {
	auth   Auth
	cfg    AppConfig
	reauth func() (Auth, AppConfig, error)
}

func NewClient(auth Auth, cfg AppConfig) *Client {
	return &Client{auth: auth, cfg: cfg}
}

func (c *Client) SetReauth(f func() (Auth, AppConfig, error)) {
	c.reauth = f
}

func (c *Client) reauthenticate() bool {
	if c.reauth == nil {
		return false
	}
	auth, cfg, err := c.reauth()
	if err != nil {
		return false
	}
	c.auth = auth
	c.cfg = cfg
	return true
}

func (c *Client) Invoke(functionName string, serializedParameters []byte) ([]byte, error) {
	result, err := c.invokeOnce(functionName, serializedParameters)
	if result != nil && result.StatusCode == statusUnauthorized && c.reauthenticate() {
		result, err = c.invokeOnce(functionName, serializedParameters)
	}
	if result != nil && result.StatusCode != 200 {
		return nil, fmt.Errorf("cloudkit: code/invoke %s status %d: body=%q resp-headers: %s", functionName, result.StatusCode, snippet(result.Body), respHeaders(result.Headers))
	}
	if err != nil {
		return nil, fmt.Errorf("cloudkit: code/invoke %s: %w", functionName, err)
	}
	if result == nil {
		return nil, fmt.Errorf("cloudkit: code/invoke %s: no response", functionName)
	}
	respMsg, err := octagon.UnframeCodeInvoke(result.Body)
	if err != nil {
		return nil, fmt.Errorf("cloudkit: code/invoke %s: %w", functionName, err)
	}
	return octagon.DecodeCodeInvokeResponse(respMsg)
}

func (c *Client) invokeOnce(functionName string, serializedParameters []byte) (*types.HTTPResult, error) {
	header := BuildCodeInvokeHeader(c.auth.Header)
	reqOp := octagon.EncodeCodeInvokeRequest("Cuttlefish", functionName, uuid.New(), serializedParameters, header)
	body := octagon.FrameCodeInvoke(reqOp)

	headers := buildHeaders(c.auth, c.cfg.UserID)
	headers["Content-Type"] = "application/x-protobuf"

	codeBase := strings.Replace(c.cfg.DatabaseURL, "-ckdatabase.", "-ckcoderouter.", 1)

	return http.ExecuteRequest(codeBase+"/api/client/code/invoke",
		http.Method("POST"),
		http.Body(body),
		http.Headers(headers),
		http.Timeout(60*time.Second),
	)
}

func snippet(b []byte) string {
	const maxSize = 200
	if len(b) > maxSize {
		return string(b[:maxSize]) + "..."
	}
	return string(b)
}

func respHeaders(h map[string][]string) string {
	if len(h) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		parts = append(parts, k+"="+strings.Join(v, ","))
	}
	sort.Strings(parts)
	return strings.Join(parts, " | ")
}
