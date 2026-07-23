package keychain

import "time"

type WiFiPassword struct {
	SSID     string
	Password string
	Created  time.Time
	Modified time.Time
}

func WiFiPasswords(items []Item) []WiFiPassword {
	var result []WiFiPassword
	for _, it := range items {
		if it.Class != "genp" || asString(it.Attrs["svce"]) != "AirPort" {
			continue
		}
		ssid := it.Acct
		if ssid == "" {
			ssid = it.Labl
		}
		wp := WiFiPassword{SSID: ssid, Password: string(it.Data)}
		if cdat, ok := it.Attrs["cdat"].(time.Time); ok {
			wp.Created = cdat
		}
		if mdat, ok := it.Attrs["mdat"].(time.Time); ok {
			wp.Modified = mdat
		}
		result = append(result, wp)
	}
	return result
}
