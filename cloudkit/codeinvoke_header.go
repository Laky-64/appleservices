package cloudkit

import "github.com/Laky-64/appleservices/internal/protobuf"

type CodeInvokeHeader struct {
	Container        string
	Bundle           string
	AppVersion       string
	OSVersion        string
	DeviceClass      string
	Platform         string
	ClientVersion    string
	ProtocolVersion  string
	ComputerName     string
	DeviceID         string
	Group            string
	MMCSPlistSHA256  string
	MMCSPlistVersion string
	MMCSProtoVersion string
	MMCSClientInfo   string
}

func BuildCodeInvokeHeader(h CodeInvokeHeader) []byte {
	if h == (CodeInvokeHeader{}) {
		return nil
	}
	w := protobuf.NewWriter()
	writeStr := func(field int, v string) {
		if v != "" {
			w.WriteBytes(field, []byte(v))
		}
	}
	writeStr(2, h.Container)
	writeStr(3, h.Bundle)
	writeStr(4, h.AppVersion)
	writeStr(8, h.OSVersion)
	writeStr(9, h.DeviceClass)
	writeStr(10, h.Platform)
	writeStr(11, h.ClientVersion)
	w.WriteVarint(16, 1)
	writeStr(18, h.ProtocolVersion)
	w.WriteVarint(19, 1)
	writeStr(21, h.ComputerName)
	writeStr(22, h.DeviceID)
	w.WriteVarint(23, 1)
	w.WriteVarint(25, 2)
	writeStr(26, h.Group)

	kv := protobuf.NewWriter()
	addKV := func(key, val string) {
		if val == "" {
			return
		}
		e := protobuf.NewWriter()
		e.WriteBytes(1, []byte(key))
		e.WriteBytes(2, []byte(val))
		kv.WriteBytes(1, e.Bytes())
	}
	addKV("x-apple-mmcs-plist-sha256", h.MMCSPlistSHA256)
	addKV("x-apple-mmcs-plist-version", h.MMCSPlistVersion)
	addKV("x-apple-mmcs-proto-version", h.MMCSProtoVersion)
	addKV("x-mme-client-info", h.MMCSClientInfo)
	kv.WriteVarint(2, 0)
	w.WriteBytes(30, kv.Bytes())

	return w.Bytes()
}
