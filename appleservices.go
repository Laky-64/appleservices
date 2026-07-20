package appleservices

import "github.com/Laky-64/appleservices/gsa"

type Store interface {
	LoadDevice() (*Device, error)
	SaveDevice(*Device) error
	LoadSession() (*Session, error)
	SaveSession(*Session) error
}

type Device struct {
	Identifier       []byte
	ProvisioningBlob []byte
}

type Session struct {
	DSID    string
	Cookies []Cookie
}

type Cookie struct {
	URL   string
	Name  string
	Value string
}

type Credentials struct {
	AppleID  string
	Password string
}

type Option func(*options)

type options struct {
	anisette   gsa.AnisetteProvider
	newBackend backendFactory
}

func WithAnisette(p gsa.AnisetteProvider) Option {
	return func(o *options) {
		o.anisette = p
	}
}
