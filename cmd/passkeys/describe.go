package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"slices"
)

var visibleAttrs = map[string]bool{
	"class": true, "agrp": true, "pdmn": true, "kcls": true, "type": true,
	"bsiz": true, "esiz": true, "perm": true, "priv": true, "modi": true,
	"sign": true, "decr": true, "encr": true, "unwp": true, "wrap": true,
	"vrfy": true, "drve": true, "sync": true, "tomb": true,
	"asen": true, "crtr": true, "extr": true, "next": true, "sens": true,
	"snrc": true, "vyrc": true, "edat": true, "sdat": true,
}

func describeAttrs(attrs map[string]any) []string {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]string, 0, len(names))
	for _, name := range names {
		value := attrs[name]
		size := 0
		switch v := value.(type) {
		case string:
			size = len(v)
		case []byte:
			size = len(v)
		}
		shown := "-"
		if visibleAttrs[name] {
			shown = fmt.Sprint(value)
		}
		out = append(out, fmt.Sprintf("%s\t%T\tlen=%d\t%s", name, value, size, shown))
	}
	return out
}

func keyLabelRelations(attrs map[string]any) string {
	klbl, _ := attrs["klbl"].([]byte)
	alis, _ := attrs["alis"].([]byte)
	data, _ := attrs["v_Data"].([]byte)
	pubMatch := false
	if len(data) == 97 {
		sum := sha1.Sum(data[:65])
		pubMatch = bytes.Equal(klbl, sum[:])
	}
	return fmt.Sprintf("klbl=alis:%t klbl=sha1(pub):%t", bytes.Equal(klbl, alis), pubMatch)
}
