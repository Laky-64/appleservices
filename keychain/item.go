package keychain

type Item struct {
	Class string
	Agrp  string
	Srvr  string
	Acct  string
	Labl  string
	Attrs map[string]any
	Data  []byte
}
