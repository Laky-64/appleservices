package appleservices

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/Laky-64/appleservices/anisette"
	"github.com/Laky-64/appleservices/ckks"
	"github.com/Laky-64/appleservices/cloudkit"
	"github.com/Laky-64/appleservices/escrow"
	"github.com/Laky-64/appleservices/gsa"
	"github.com/Laky-64/appleservices/icloud"
	"github.com/Laky-64/appleservices/internal/protobuf"
	"github.com/Laky-64/appleservices/keychain"
	"github.com/Laky-64/appleservices/octagon"
)

const (
	ckContainerID = "com.apple.security.keychain"
	ckBundleID    = "com.apple.security.cuttlefish"
)

type loginBackend interface {
	Login(username, password string) (*gsa.LoginResult, error)
	RequestTrustedDeviceCode(dsid, idmsToken string) error
	SubmitTrustedDeviceCode(dsid, idmsToken, code string) error
	Snapshot(dsid string, tokens map[string]string) (gsa.Session, error)
}

type backendFactory func(anisette gsa.AnisetteProvider, sess *gsa.Session) loginBackend

func defaultBackend(anis gsa.AnisetteProvider, sess *gsa.Session) loginBackend {
	if sess != nil {
		return gsa.NewClientFromSession(anis, *sess)
	}
	return gsa.NewClient(anis)
}

type Login struct {
	creds          Credentials
	store          Store
	backend        loginBackend
	anisette       gsa.AnisetteProvider
	stateful       *anisette.Provider
	needsTwoFactor bool
	result         *gsa.LoginResult
	adsid          string
	idmsToken      string
}

func BeginLogin(creds Credentials, store Store, opts ...Option) (*Login, error) {
	if store == nil {
		return nil, errors.New("appleservices: store is required")
	}
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}
	if o.newBackend == nil {
		o.newBackend = defaultBackend
	}

	dev, err := store.LoadDevice()
	if err != nil {
		return nil, fmt.Errorf("appleservices: load device: %w", err)
	}

	l := &Login{creds: creds, store: store}

	if o.anisette != nil {
		l.anisette = o.anisette
	} else {
		var st anisette.State
		if dev != nil && len(dev.Identifier) == 16 {
			st = anisette.State{Identifier: dev.Identifier, AdiPB: dev.ProvisioningBlob}
		} else {
			st = anisette.NewState()
		}
		p := anisette.NewProviderFromState(st, nil)
		l.stateful = p
		l.anisette = p
	}

	sess, err := store.LoadSession()
	if err != nil {
		return nil, fmt.Errorf("appleservices: load session: %w", err)
	}
	var gsess *gsa.Session
	if sess != nil {
		gsess = new(toGSASession(*sess))
	}
	l.backend = o.newBackend(l.anisette, gsess)

	if gsess != nil {
		l.needsTwoFactor = false
		l.adsid = gsess.DSID
	} else {
		res, err := l.backend.Login(creds.AppleID, creds.Password)
		if err != nil {
			return nil, fmt.Errorf("appleservices: login: %w", err)
		}
		l.result = res
		l.needsTwoFactor = res.NeedsTwoFactor
		if res.SessionPayload != nil {
			l.adsid = spdString(res.SessionPayload, "adsid")
			l.idmsToken = spdString(res.SessionPayload, "GsIdmsToken")
		}
	}

	if err := l.persistDevice(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Login) persistDevice() error {
	if l.stateful == nil {
		return nil
	}
	st := l.stateful.State()
	if len(st.Identifier) == 0 {
		return nil
	}
	if err := l.store.SaveDevice(&Device{Identifier: st.Identifier, ProvisioningBlob: st.AdiPB}); err != nil {
		return fmt.Errorf("appleservices: save device: %w", err)
	}
	return nil
}

func (l *Login) NeedsTwoFactor() bool { return l.needsTwoFactor }

func (l *Login) RequestCode() error {
	if !l.needsTwoFactor {
		return errors.New("appleservices: no two-factor challenge is pending")
	}
	if l.adsid == "" || l.idmsToken == "" {
		return errors.New("appleservices: two-factor challenge missing adsid/GsIdmsToken")
	}
	return l.backend.RequestTrustedDeviceCode(l.adsid, l.idmsToken)
}

func (l *Login) SubmitCode(code string) error {
	if !l.needsTwoFactor {
		return errors.New("appleservices: no two-factor challenge is pending")
	}
	if err := l.backend.SubmitTrustedDeviceCode(l.adsid, l.idmsToken, code); err != nil {
		return fmt.Errorf("appleservices: submit code: %w", err)
	}
	res, err := l.backend.Login(l.creds.AppleID, l.creds.Password)
	if err != nil {
		return fmt.Errorf("appleservices: re-login after 2FA: %w", err)
	}
	if res.NeedsTwoFactor {
		return errors.New("appleservices: still prompted for 2FA after submitting a code")
	}
	l.result = res
	l.needsTwoFactor = false
	if res.SessionPayload != nil {
		l.adsid = spdString(res.SessionPayload, "adsid")
	}

	tokens := stringValues(res.SessionPayload)
	g, err := l.backend.Snapshot(l.adsid, tokens)
	if err != nil {
		return fmt.Errorf("appleservices: snapshot session: %w", err)
	}
	if err := l.store.SaveSession(new(fromGSASession(g))); err != nil {
		return fmt.Errorf("appleservices: save session: %w", err)
	}
	return nil
}

func (l *Login) Client() (*Client, error) {
	if l.needsTwoFactor {
		return nil, errors.New("appleservices: two-factor authentication required; submit a code first")
	}

	spd, err := l.spd()
	if err != nil {
		return nil, err
	}
	pet, err := icloud.PETFromSPD(spd)
	if err != nil {
		return nil, err
	}

	delegAnis, err := l.anisette.Headers()
	if err != nil {
		return nil, fmt.Errorf("appleservices: anisette headers: %w", err)
	}
	dt, err := icloud.FetchDelegateTokens(delegAnis, l.creds.AppleID, l.adsid, pet)
	if err != nil {
		return nil, fmt.Errorf("appleservices: delegate tokens: %w", err)
	}
	ckTok := dt.CloudKitToken
	if ckTok == "" {
		ckTok = dt.MMEAuthToken
	}

	appInitAnis, err := l.anisette.Headers()
	if err != nil {
		return nil, fmt.Errorf("appleservices: anisette headers: %w", err)
	}
	deviceID := fmt.Sprintf("%x", sha256.Sum256([]byte(appInitAnis["X-Mme-Device-Id"]+dt.DSID)))
	computerName, _ := os.Hostname()
	if computerName == "" {
		computerName = "appleservices"
	}
	auth := cloudkit.Auth{
		DSID:            dt.DSID,
		MMEAuthToken:    dt.MMEAuthToken,
		CloudKitToken:   ckTok,
		AnisetteHeaders: appInitAnis,
		ContainerID:     ckContainerID,
		BundleID:        ckBundleID,
		Header: cloudkit.CodeInvokeHeader{
			Container:       ckContainerID,
			Bundle:          ckBundleID,
			AppVersion:      "15.8.0.127",
			OSVersion:       "Windows; 10.0.26200.8875; Win11 Professional; x64",
			DeviceClass:     "PC",
			Platform:        "CloudKitWin",
			ClientVersion:   "168.1.0.0",
			ProtocolVersion: "5.0",
			ComputerName:    computerName,
			DeviceID:        deviceID,
			Group:           "EphemeralGroup",
			MMCSClientInfo:  appInitAnis["X-Mme-Client-Info"],
		},
	}
	cfg, err := cloudkit.AppInit(auth)
	if err != nil {
		return nil, fmt.Errorf("appleservices: ckAppInit: %w", err)
	}

	return &Client{
		ck:       cloudkit.NewClient(auth, cfg),
		anisette: l.anisette,
		appleID:  l.creds.AppleID,
		password: l.creds.Password,
		mme:      dt.MMEAuthToken,
		dsid:     dt.DSID,
		altDSID:  l.adsid,
		mintPET:  l.freshPET,
	}, nil
}

func (l *Login) spd() (map[string]any, error) {
	if l.result != nil && l.result.SessionPayload != nil {
		return l.result.SessionPayload, nil
	}
	pet, adsid, spd, err := l.reLogin()
	if err != nil {
		return nil, err
	}
	_ = pet
	if l.adsid == "" {
		l.adsid = adsid
	}
	return spd, nil
}

func (l *Login) freshPET() (pet, adsid string, err error) {
	pet, adsid, _, err = l.reLogin()
	return pet, adsid, err
}

func (l *Login) reLogin() (pet, adsid string, spd map[string]any, err error) {
	res, err := l.backend.Login(l.creds.AppleID, l.creds.Password)
	if err != nil {
		return "", "", nil, fmt.Errorf("appleservices: login: %w", err)
	}
	if res.NeedsTwoFactor {
		return "", "", nil, errors.New("appleservices: unexpected two-factor challenge")
	}
	if res.SessionPayload == nil {
		return "", "", nil, errors.New("appleservices: login returned no session payload")
	}
	l.result = res
	p, err := icloud.PETFromSPD(res.SessionPayload)
	if err != nil {
		return "", "", nil, err
	}
	return p, spdString(res.SessionPayload, "adsid"), res.SessionPayload, nil
}

type Client struct {
	ck       *cloudkit.Client
	anisette gsa.AnisetteProvider
	appleID  string
	password string
	mme      string
	dsid     string
	altDSID  string
	mintPET  func() (pet, adsid string, err error)
}

func (c *Client) Vault(passcode string) (*ckks.Vault, error) {
	refs, err := c.ViableBottles()
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, errors.New("appleservices: no viable bottles for this account")
	}
	return c.openVaultWith(refs[0].bottle, passcode)
}

type BottleDevice = octagon.BottleDevice

type BottleRef struct {
	Device BottleDevice
	bottle octagon.Bottle
}

func (c *Client) ViableBottles() ([]BottleRef, error) {
	vb, err := octagon.FetchViableBottles(c.ck)
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch viable bottles: %w", err)
	}
	all := append(append([]octagon.Bottle{}, vb.Viable...), vb.Partial...)
	refs := make([]BottleRef, 0, len(all))
	for _, b := range all {
		refs = append(refs, BottleRef{Device: b.Device, bottle: b})
	}
	return refs, nil
}

func (c *Client) openVaultWith(bottle octagon.Bottle, passcode string) (*ckks.Vault, error) {
	enc, peerID, err := c.recoverPeer(bottle, passcode)
	if err != nil {
		return nil, err
	}
	return ckks.OpenVault(c.ck, enc, peerID), nil
}

func (c *Client) recoverPeer(bottle octagon.Bottle, passcode string) (*ecdsa.PrivateKey, string, error) {
	pet, adsid, err := c.mintPET()
	if err != nil {
		return nil, "", fmt.Errorf("appleservices: mint escrow PET: %w", err)
	}
	if adsid == "" {
		adsid = c.altDSID
	}

	discoverAnis, err := c.anisette.Headers()
	if err != nil {
		return nil, "", fmt.Errorf("appleservices: anisette headers: %w", err)
	}
	escrowURL, err := escrow.DiscoverURL(c.mme, c.dsid, discoverAnis)
	if err != nil {
		return nil, "", fmt.Errorf("appleservices: discover escrow url: %w", err)
	}
	escrowAnis, err := c.anisette.Headers()
	if err != nil {
		return nil, "", fmt.Errorf("appleservices: anisette headers: %w", err)
	}
	esc := escrow.NewClient(escrowURL, escrowAnis)

	entropy, err := esc.Recover(c.appleID, c.password, pet, c.dsid, passcode, bottle.BottleID, bottle.EscrowRecordLabel)
	if err != nil {
		return nil, "", fmt.Errorf("appleservices: escrow recover: %w", err)
	}

	_, enc, err := octagon.DecryptBottle(entropy, adsid, bottle.Contents)
	if err != nil {
		return nil, "", fmt.Errorf("appleservices: decrypt bottle: %w", err)
	}
	peerID := bottle.PeerID
	if peerID == "" {
		peerID = sponsorPeerID(bottle.Contents)
	}
	if peerID == "" {
		return nil, "", errors.New("appleservices: decrypted bottle has no sponsor peerID")
	}
	return enc, peerID, nil
}

type PeerKey struct {
	PeerID     string
	PrivateKey []byte
}

func (c *Client) RecoverPeer(passcode string) (PeerKey, error) {
	refs, err := c.ViableBottles()
	if err != nil {
		return PeerKey{}, err
	}
	if len(refs) == 0 {
		return PeerKey{}, errors.New("appleservices: no viable bottles for this account")
	}
	return c.RecoverPeerWith(refs[0], passcode)
}

func (c *Client) RecoverPeerWith(ref BottleRef, passcode string) (PeerKey, error) {
	enc, peerID, err := c.recoverPeer(ref.bottle, passcode)
	if err != nil {
		return PeerKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(enc)
	if err != nil {
		return PeerKey{}, fmt.Errorf("appleservices: marshal peer key: %w", err)
	}
	return PeerKey{PeerID: peerID, PrivateKey: der}, nil
}

func (c *Client) VaultWithPeer(pk PeerKey) (*ckks.Vault, error) {
	if pk.PeerID == "" {
		return nil, errors.New("appleservices: peer key has no PeerID")
	}
	key, err := x509.ParsePKCS8PrivateKey(pk.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("appleservices: parse peer key: %w", err)
	}
	enc, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("appleservices: peer key is %T, want an ECDSA private key", key)
	}
	return ckks.OpenVault(c.ck, enc, pk.PeerID), nil
}

func (c *Client) OpenPasswordsWithPeer(pk PeerKey) (*PasswordVault, error) {
	v, err := c.VaultWithPeer(pk)
	if err != nil {
		return nil, err
	}
	return &PasswordVault{v: v}, nil
}

type Profile struct {
	Name      string
	Photo     []byte
	PhotoType string
}

func (c *Client) Profile() (Profile, error) {
	anis, err := c.anisette.Headers()
	if err != nil {
		return Profile{}, fmt.Errorf("appleservices: anisette headers: %w", err)
	}
	bag, err := icloud.FetchAccountBag(c.mme, c.dsid, anis)
	if err != nil {
		return Profile{}, err
	}
	name := icloud.AccountFullName(bag)
	photo, ptype, err := icloud.ProfilePhoto(icloud.ContactsDAVURL(bag), name, c.mme, c.dsid, anis)
	if err != nil {
		return Profile{}, err
	}
	return Profile{Name: name, Photo: photo, PhotoType: ptype}, nil
}

func (c *Client) WebPasswords(passcode string) ([]keychain.WebPassword, error) {
	pv, err := c.OpenPasswords(passcode)
	if err != nil {
		return nil, err
	}
	return pv.WebPasswords()
}

type PasswordVault struct {
	v *ckks.Vault
}

func (c *Client) OpenPasswords(passcode string) (*PasswordVault, error) {
	v, err := c.Vault(passcode)
	if err != nil {
		return nil, err
	}
	return &PasswordVault{v: v}, nil
}

func (c *Client) OpenPasswordsWith(ref BottleRef, passcode string) (*PasswordVault, error) {
	v, err := c.openVaultWith(ref.bottle, passcode)
	if err != nil {
		return nil, err
	}
	return &PasswordVault{v: v}, nil
}

func (pv *PasswordVault) WebPasswords() ([]keychain.WebPassword, error) {
	items, err := pv.v.Items("Passwords")
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch Passwords view: %w", err)
	}
	return keychain.WebPasswords(items), nil
}

func sponsorPeerID(otBottle []byte) string {
	if fs, err := protobuf.ReadFields(otBottle); err == nil {
		for _, f := range fs {
			if f.Number == 1 {
				return string(f.Bytes)
			}
		}
	}
	return ""
}

func toGSASession(s Session) gsa.Session {
	cookies := map[string][]gsa.CookieKV{}
	for _, c := range s.Cookies {
		cookies[c.URL] = append(cookies[c.URL], gsa.CookieKV{Name: c.Name, Value: c.Value})
	}
	return gsa.Session{DSID: s.DSID, Cookies: cookies}
}

func fromGSASession(g gsa.Session) Session {
	var cookies []Cookie
	for url, kvs := range g.Cookies {
		for _, kv := range kvs {
			cookies = append(cookies, Cookie{URL: url, Name: kv.Name, Value: kv.Value})
		}
	}
	return Session{DSID: g.DSID, Cookies: cookies}
}

func spdString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func stringValues(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
