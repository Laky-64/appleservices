package anisette

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Laky-64/http"
)

var errNotProvisioned = errors.New("anisette: device not provisioned")

type Client struct {
	url        string
	clientInfo string
	userAgent  string
}

func NewClient(url string) (*Client, error) {
	c := &Client{url: strings.TrimRight(url, "/")}
	var info struct {
		ClientInfo string `json:"client_info"`
		UserAgent  string `json:"user_agent"`
	}
	result, err := http.ExecuteRequest(c.url+"/v3/client_info", http.Timeout(30*time.Second))
	if result != nil && result.StatusCode != 200 {
		return nil, fmt.Errorf("anisette: client_info status %d", result.StatusCode)
	}
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("anisette: client_info: no response")
	}
	if err := json.Unmarshal(result.Body, &info); err != nil {
		return nil, err
	}
	c.clientInfo, c.userAgent = info.ClientInfo, info.UserAgent
	return c, nil
}

func (c *Client) GetHeaders(s State) (map[string]string, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"identifier": base64.StdEncoding.EncodeToString(s.Identifier),
		"adi_pb":     base64.StdEncoding.EncodeToString(s.AdiPB),
	})
	result, err := http.ExecuteRequest(c.url+"/v3/get_headers",
		http.Method("POST"),
		http.Body(reqBody),
		http.Headers(map[string]string{"Content-Type": "application/json"}),
		http.Timeout(30*time.Second),
	)
	if result == nil {
		return nil, err
	}
	if result.StatusCode != 200 {
		return nil, fmt.Errorf("anisette: get_headers status %d", result.StatusCode)
	}

	var r struct {
		Result  string `json:"result"`
		Message string `json:"message"`
		MD      string `json:"X-Apple-I-MD"`
		MDM     string `json:"X-Apple-I-MD-M"`
		RINFO   string `json:"X-Apple-I-MD-RINFO"`
	}
	if err := json.Unmarshal(result.Body, &r); err != nil {
		return nil, fmt.Errorf("anisette: get_headers decode: %w", err)
	}
	if r.Result != "Headers" {
		if strings.Contains(r.Message, "-45061") {
			return nil, errNotProvisioned
		}
		return nil, fmt.Errorf("anisette: get_headers error: %s", r.Message)
	}
	rinfo := r.RINFO
	if rinfo == "" {
		rinfo = "17106176"
	}
	return map[string]string{
		"X-Apple-I-MD":          r.MD,
		"X-Apple-I-MD-M":        r.MDM,
		"X-Apple-I-MD-RINFO":    rinfo,
		"X-Apple-I-MD-LU":       s.MDLU(),
		"X-Apple-I-SRL-NO":      "0",
		"X-Mme-Client-Info":     c.clientInfo,
		"X-Mme-Device-Id":       s.DeviceID(),
		"X-Apple-I-Client-Time": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"X-Apple-I-TimeZone":    "GMT",
	}, nil
}
