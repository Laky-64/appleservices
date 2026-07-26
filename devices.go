package appleservices

import (
	"fmt"
	"strings"

	"github.com/Laky-64/appleservices/icloud"
)

type AccountDevice = icloud.AccountDevice

func (c *Client) Devices() ([]AccountDevice, error) {
	adsid, gsIdmsToken, err := c.mintIdentity()
	if err != nil {
		return nil, fmt.Errorf("appleservices: mint identity token: %w", err)
	}
	if adsid == "" {
		adsid = c.altDSID
	}
	anis, err := c.anisette.Headers()
	if err != nil {
		return nil, fmt.Errorf("appleservices: anisette headers: %w", err)
	}
	devs, err := icloud.FetchDevices(anis, icloud.IdentityToken(adsid, gsIdmsToken))
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch devices: %w", err)
	}
	return devs, nil
}

func classFamily(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "ipad"):
		return "ipad"
	case strings.Contains(l, "iphone"):
		return "iphone"
	case strings.Contains(l, "ipod"):
		return "ipod"
	case strings.Contains(l, "watch"):
		return "watch"
	case strings.Contains(l, "mac") || strings.Contains(l, "imac"):
		return "mac"
	default:
		return l
	}
}

func deviceImageURL(d *icloud.AccountDevice) string {
	if d.ListImageURL2x != "" {
		return d.ListImageURL2x
	}
	return d.ListImageURL
}

func matchDevice(b BottleDevice, devices []icloud.AccountDevice) *icloud.AccountDevice {
	fam := classFamily(b.Class)
	var candidates []icloud.AccountDevice
	for _, d := range devices {
		if classFamily(d.DeviceClass) == fam || classFamily(d.OS) == fam {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 1 {
		return &candidates[0]
	}
	if len(candidates) == 0 {
		return nil
	}
	var named []icloud.AccountDevice
	for _, d := range candidates {
		if b.Name != "" && strings.EqualFold(d.Name, b.Name) {
			named = append(named, d)
		}
	}
	if len(named) == 1 {
		return &named[0]
	}
	var modeled []icloud.AccountDevice
	bm := strings.ToLower(b.Model)
	for _, d := range candidates {
		if d.ModelName != "" && strings.Contains(bm, strings.ToLower(d.ModelName)) {
			modeled = append(modeled, d)
		}
	}
	if len(modeled) == 1 {
		return &modeled[0]
	}
	return nil
}
