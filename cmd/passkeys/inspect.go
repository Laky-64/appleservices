package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/keychain"
	"howett.net/plist"
)

const testMarker = "renvault"

func inspectTest(kc *appleservices.KeychainVault) error {
	items, err := kc.Items()
	if err != nil {
		return fmt.Errorf("items: %w", err)
	}
	sites := map[string]bool{}
	for _, it := range items {
		if it.Class == "keys" && mentionsTest(it.Attrs["atag"]) {
			sites[it.Labl] = true
		}
	}
	n := 0
	for _, it := range items {
		inner := innerPlist(it)
		visible := make(map[string]any, len(it.Attrs))
		for name, value := range it.Attrs {
			if name != "v_Data" {
				visible[name] = value
			}
		}
		if !mentionsTest(visible) && !mentionsTest(inner) && !(it.Agrp == "com.apple.password-manager" && sites[it.Srvr]) {
			continue
		}
		n++
		fmt.Printf("item %d class=%s agrp=%s record=%s\n", n, it.Class, it.Agrp, it.Name)
		for _, line := range showAttrs(it) {
			fmt.Println("  " + line)
		}
		if inner != nil {
			fmt.Println("  v_Data plist:")
			for _, line := range showMap(inner, "    ") {
				fmt.Println(line)
			}
		}
	}
	fmt.Printf("%d items mention %q\n", n, testMarker)
	return nil
}

func innerPlist(it keychain.Item) map[string]any {
	if it.Class == "keys" || len(it.Data) == 0 {
		return nil
	}
	var doc map[string]any
	if _, err := plist.Unmarshal(it.Data, &doc); err != nil {
		return nil
	}
	return doc
}

func mentionsTest(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(strings.ToLower(x), testMarker)
	case []byte:
		return bytes.Contains(bytes.ToLower(x), []byte(testMarker))
	case map[string]any:
		for _, e := range x {
			if mentionsTest(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if mentionsTest(e) {
				return true
			}
		}
	}
	return false
}

func showAttrs(it keychain.Item) []string {
	names := make([]string, 0, len(it.Attrs))
	for name := range it.Attrs {
		names = append(names, name)
	}
	slices.Sort(names)
	var out []string
	for _, name := range names {
		if name == "v_Data" {
			out = append(out, fmt.Sprintf("v_Data\tlen=%d\t(hidden)", len(it.Data)))
			continue
		}
		out = append(out, name+"\t"+showValue(it.Attrs[name]))
	}
	return out
}

func showMap(m map[string]any, indent string) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	var out []string
	for _, name := range names {
		if sub, ok := m[name].(map[string]any); ok {
			out = append(out, indent+name+":")
			out = append(out, showMap(sub, indent+"  ")...)
			continue
		}
		out = append(out, indent+name+"\t"+showValue(m[name]))
	}
	return out
}

func showValue(v any) string {
	switch x := v.(type) {
	case []byte:
		if printable(x) {
			return fmt.Sprintf("bytes %q", x)
		}
		return "hex " + hex.EncodeToString(x)
	case map[string]any:
		return "{" + strings.Join(showMap(x, ""), "; ") + "}"
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, showValue(e))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%T %v", v, v)
	}
}

func printable(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
