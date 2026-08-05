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
	"github.com/Laky-64/appleservices/internal/uuid"
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
	RequestSMSCode(dsid, idmsToken string) error
	SubmitSMSCode(dsid, idmsToken, code string) error
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

type TwoFactorMethod int

const (
	TrustedDevice TwoFactorMethod = iota
	SMS
)

func (l *Login) RequestCode(method TwoFactorMethod) error {
	if !l.needsTwoFactor {
		return errors.New("appleservices: no two-factor challenge is pending")
	}
	if l.adsid == "" || l.idmsToken == "" {
		return errors.New("appleservices: two-factor challenge missing adsid/GsIdmsToken")
	}
	switch method {
	case TrustedDevice:
		return l.backend.RequestTrustedDeviceCode(l.adsid, l.idmsToken)
	case SMS:
		return l.backend.RequestSMSCode(l.adsid, l.idmsToken)
	default:
		return fmt.Errorf("appleservices: unknown two-factor method %d", method)
	}
}

func (l *Login) SubmitCode(method TwoFactorMethod, code string) error {
	if !l.needsTwoFactor {
		return errors.New("appleservices: no two-factor challenge is pending")
	}
	var err error
	switch method {
	case TrustedDevice:
		err = l.backend.SubmitTrustedDeviceCode(l.adsid, l.idmsToken, code)
	case SMS:
		err = l.backend.SubmitSMSCode(l.adsid, l.idmsToken, code)
	default:
		return fmt.Errorf("appleservices: unknown two-factor method %d", method)
	}
	if err != nil {
		return fmt.Errorf("appleservices: submit code: %w", err)
	}
	return l.finishTwoFactor()
}

func (l *Login) finishTwoFactor() error {
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

	auth, cfg, dt, err := l.cloudKitAuth(pet)
	if err != nil {
		return nil, err
	}

	c := &Client{
		ck:           cloudkit.NewClient(auth, cfg),
		anisette:     l.anisette,
		appleID:      l.creds.AppleID,
		password:     l.creds.Password,
		mme:          dt.MMEAuthToken,
		dsid:         dt.DSID,
		altDSID:      l.adsid,
		mintPET:      l.freshPET,
		mintIdentity: l.freshIdentity,
	}
	c.ck.SetReauth(func() (cloudkit.Auth, cloudkit.AppConfig, error) {
		freshPET, adsid, err := l.freshPET()
		if err != nil {
			return cloudkit.Auth{}, cloudkit.AppConfig{}, err
		}
		if adsid != "" {
			l.adsid = adsid
			c.altDSID = adsid
		}
		auth, cfg, dt, err := l.cloudKitAuth(freshPET)
		if err != nil {
			return cloudkit.Auth{}, cloudkit.AppConfig{}, err
		}
		c.mme = dt.MMEAuthToken
		c.dsid = dt.DSID
		return auth, cfg, nil
	})
	return c, nil
}

func (l *Login) cloudKitAuth(pet string) (cloudkit.Auth, cloudkit.AppConfig, icloud.DelegateTokens, error) {
	delegAnis, err := l.anisette.Headers()
	if err != nil {
		return cloudkit.Auth{}, cloudkit.AppConfig{}, icloud.DelegateTokens{}, fmt.Errorf("appleservices: anisette headers: %w", err)
	}
	dt, err := icloud.FetchDelegateTokens(delegAnis, l.creds.AppleID, l.adsid, pet)
	if err != nil {
		return cloudkit.Auth{}, cloudkit.AppConfig{}, icloud.DelegateTokens{}, fmt.Errorf("appleservices: delegate tokens: %w", err)
	}
	ckTok := dt.CloudKitToken
	if ckTok == "" {
		ckTok = dt.MMEAuthToken
	}

	appInitAnis, err := l.anisette.Headers()
	if err != nil {
		return cloudkit.Auth{}, cloudkit.AppConfig{}, icloud.DelegateTokens{}, fmt.Errorf("appleservices: anisette headers: %w", err)
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
		return cloudkit.Auth{}, cloudkit.AppConfig{}, icloud.DelegateTokens{}, fmt.Errorf("appleservices: ckAppInit: %w", err)
	}
	return auth, cfg, dt, nil
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

func (l *Login) freshIdentity() (adsid, gsIdmsToken string, err error) {
	_, adsid, spd, err := l.reLogin()
	if err != nil {
		return "", "", err
	}
	return adsid, spdString(spd, "GsIdmsToken"), nil
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
	ck           *cloudkit.Client
	anisette     gsa.AnisetteProvider
	appleID      string
	password     string
	mme          string
	dsid         string
	altDSID      string
	mintPET      func() (pet, adsid string, err error)
	mintIdentity func() (adsid, gsIdmsToken string, err error)
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
	if devs, err := c.Devices(); err == nil {
		for i := range refs {
			if device := matchDevice(refs[i].Device, devs); device != nil {
				refs[i].Device.Name = device.Name
				refs[i].Device.ShortModel = device.ModelName
				refs[i].Device.OS = device.OS
				refs[i].Device.OSVersion = device.OSVersion
				refs[i].Device.ImageURL = deviceImageURL(device)
			}
		}
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

func (c *Client) RecoverPeer(ref BottleRef, passcode string) (PeerKey, error) {
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

func (c *Client) OpenKeychainWithPeer(pk PeerKey) (*KeychainVault, error) {
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
	return &KeychainVault{v: ckks.OpenVault(c.ck, enc, pk.PeerID)}, nil
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

type KeychainVault struct {
	v *ckks.Vault
}

func (c *Client) OpenKeychain(ref BottleRef, passcode string) (*KeychainVault, error) {
	v, err := c.openVaultWith(ref.bottle, passcode)
	if err != nil {
		return nil, err
	}
	return &KeychainVault{v: v}, nil
}

func (pv *KeychainVault) Items() ([]keychain.Item, error) {
	items, err := pv.v.Items("Passwords")
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch Passwords view: %w", err)
	}
	return items, nil
}

func (pv *KeychainVault) WebPasswords() ([]keychain.WebPassword, error) {
	items, err := pv.v.Items("Passwords")
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch Passwords view: %w", err)
	}
	return keychain.WebPasswords(items), nil
}

func (pv *KeychainVault) Groups() ([]keychain.Group, error) {
	items, err := pv.v.Items("Passwords")
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch Passwords view: %w", err)
	}
	return keychain.Groups(items), nil
}

func (pv *KeychainVault) WiFiPasswords() ([]keychain.WiFiPassword, error) {
	items, err := pv.v.Items("WiFi")
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch WiFi view: %w", err)
	}
	return keychain.WiFiPasswords(items), nil
}

func (pv *KeychainVault) Passkeys() ([]keychain.Passkey, error) {
	items, err := pv.v.Items("Passwords")
	if err != nil {
		return nil, fmt.Errorf("appleservices: fetch Passwords view: %w", err)
	}
	return keychain.Passkeys(items), nil
}

const (
	agrpWebauthn        = "com.apple.webkit.webauthn"
	agrpWebauthnDeleted = "com.apple.webkit.webauthn-recently-deleted"
)

func (pv *KeychainVault) DeletePasskeys(pks []keychain.Passkey) []BulkResult[keychain.Passkey] {
	out := make([]BulkResult[keychain.Passkey], len(pks))
	anyValid := false
	for i, pk := range pks {
		out[i] = BulkResult[keychain.Passkey]{Entry: pk}
		if pk.IsDeleted {
			out[i].Err = fmt.Errorf("appleservices: DeletePasskeys: passkey %q is already deleted", pk.RelyingParty)
			continue
		}
		if pk.Record.RecordName == "" {
			out[i].Err = fmt.Errorf("appleservices: DeletePasskeys: passkey %q has no backing record", pk.RelyingParty)
			continue
		}
		anyValid = true
	}
	if !anyValid {
		return out
	}

	items, err := pv.v.Items("Passwords")
	if err != nil {
		for i := range out {
			if out[i].Err == nil {
				out[i].Err = fmt.Errorf("appleservices: DeletePasskeys: %w", err)
			}
		}
		return out
	}

	for i, pk := range pks {
		if out[i].Err != nil {
			continue
		}
		if _, err := pv.v.MoveRecordIn("Passwords", items, pk.Record.RecordName, agrpWebauthnDeleted); err != nil {
			out[i].Err = fmt.Errorf("appleservices: DeletePasskeys (move %s): %w", pk.Record.RecordName, err)
		}
	}
	return out
}

func (pv *KeychainVault) RestorePasskey(pk keychain.Passkey) error {
	if !pk.IsDeleted || pk.Record.RecordName == "" {
		return fmt.Errorf("appleservices: RestorePasskey: passkey %q is not a deleted entry", pk.RelyingParty)
	}
	if _, err := pv.v.MoveRecord("Passwords", pk.Record.RecordName, agrpWebauthn); err != nil {
		return fmt.Errorf("appleservices: restore passkey: %w", err)
	}
	return nil
}

func (pv *KeychainVault) PurgePasskeys(pks []keychain.Passkey) []BulkResult[keychain.Passkey] {
	out := make([]BulkResult[keychain.Passkey], len(pks))
	for i, pk := range pks {
		out[i] = BulkResult[keychain.Passkey]{Entry: pk}
	}
	var refs []keychain.DeletedRef
	var owner []int
	for i, pk := range pks {
		if !pk.IsDeleted || pk.Record.RecordName == "" {
			out[i].Err = fmt.Errorf("appleservices: PurgePasskeys: passkey %q is not a deleted entry", pk.RelyingParty)
			continue
		}
		refs = append(refs, pk.Record)
		owner = append(owner, i)
	}
	if len(refs) == 0 {
		return out
	}
	results, err := pv.v.DeleteRecords("Passwords", refs)
	if err != nil {
		for _, i := range owner {
			if out[i].Err == nil {
				out[i].Err = fmt.Errorf("appleservices: PurgePasskeys batch: %w", err)
			}
		}
		return out
	}
	for j, sr := range results {
		i := owner[j]
		if out[i].Err == nil && sr.Code != 1 {
			out[i].Err = &cloudkit.SaveError{SaveResult: sr}
		}
	}
	return out
}

func (pv *KeychainVault) AddWebPassword(domain, username, password, note string) error {
	attrs, err := keychain.EncodeWebPasswordItem(domain, username, password)
	if err != nil {
		return fmt.Errorf("appleservices: %w", err)
	}
	if _, _, err := pv.v.AddItem("Passwords", attrs); err != nil {
		return fmt.Errorf("appleservices: add web password: %w", err)
	}
	if note != "" {
		meta, err := keychain.EncodeMetadataItem(domain, username, domain, note)
		if err != nil {
			return fmt.Errorf("appleservices: %w", err)
		}
		if _, _, err := pv.v.AddItem("Passwords", meta); err != nil {
			return fmt.Errorf("appleservices: web password saved but note metadata failed: %w", err)
		}
	}
	return nil
}

func (pv *KeychainVault) AddManualPassword(title, username, password, note string) error {
	return pv.AddManualPasswordWithID(uuid.New(), title, username, password, note)
}

func (pv *KeychainVault) AddManualPasswordWithID(id, title, username, password, note string) error {
	if !uuid.IsCanonical(id) {
		return fmt.Errorf("appleservices: AddManualPassword: %q is not a canonical UUID", id)
	}
	cred, err := keychain.EncodeWebPasswordItem(id, username, password)
	if err != nil {
		return fmt.Errorf("appleservices: %w", err)
	}
	if _, _, err := pv.v.AddItem("Passwords", cred); err != nil {
		return fmt.Errorf("appleservices: add manual password: %w", err)
	}

	meta, err := keychain.EncodeMetadataItem(id, username, title, note)
	if err != nil {
		return fmt.Errorf("appleservices: %w", err)
	}
	if _, _, err := pv.v.AddItem("Passwords", meta); err != nil {
		return fmt.Errorf("appleservices: manual password credential saved but title metadata failed: %w", err)
	}
	return nil
}

func (pv *KeychainVault) EditWebPassword(p keychain.WebPassword, newDomain, newUsername, newPassword string) error {
	items, err := pv.v.Items("Passwords")
	if err != nil {
		return fmt.Errorf("appleservices: edit web password: %w", err)
	}
	return pv.EditWebPasswordIn(items, p, newDomain, newUsername, newPassword)
}

func (pv *KeychainVault) EditWebPasswordIn(items []keychain.Item, p keychain.WebPassword, newDomain, newUsername, newPassword string) error {
	if p.IsDeleted {
		return fmt.Errorf("appleservices: EditWebPassword: %q is deleted; restore it first", p.Domain)
	}
	if newDomain == "" || newUsername == "" {
		return fmt.Errorf("appleservices: EditWebPassword: domain and username must be non-empty")
	}
	var credUpdated bool
	for i, it := range items {
		if it.Class == "inet" && it.Agrp == "com.apple.cfnetwork" && it.Srvr == p.Domain && it.Acct == p.Username {
			blob, err := keychain.EncodeItemRenamed(it.Attrs, newDomain, newUsername, []byte(newPassword))
			if err != nil {
				return fmt.Errorf("appleservices: %w", err)
			}
			sr, err := pv.v.UpdateItem("Passwords", it.Name, it.Etag, blob)
			if err != nil {
				return fmt.Errorf("appleservices: edit web password: %w", err)
			}
			items[i].Srvr = newDomain
			items[i].Acct = newUsername
			items[i].Data = []byte(newPassword)
			items[i].Etag = sr.Etag
			if items[i].Attrs != nil {
				items[i].Attrs["srvr"] = newDomain
				items[i].Attrs["acct"] = newUsername
				items[i].Attrs["v_Data"] = []byte(newPassword)
			}
			credUpdated = true
			break
		}
	}
	if !credUpdated {
		return fmt.Errorf("appleservices: EditWebPassword: no active entry for %q (%s)", p.Domain, p.Username)
	}
	if newDomain == p.Domain && newUsername == p.Username {
		return nil
	}
	if i := companionIndex(items, p.Domain, p.Username); i >= 0 {
		inner := keychain.DecodeCompanionInner(items[i].Data)
		if inner == nil {
			inner = map[string]any{}
		}
		if err := pv.writeCompanion(items, i, newDomain, newUsername, inner); err != nil {
			return fmt.Errorf("appleservices: edit web password (rename companion): %w", err)
		}
	}
	return nil
}

type Metadata struct {
	Title string
	Note  string
	TOTP  string
}

func (pv *KeychainVault) SetMetadata(p keychain.WebPassword, m Metadata) error {
	items, err := pv.v.Items("Passwords")
	if err != nil {
		return fmt.Errorf("appleservices: set metadata: %w", err)
	}
	return pv.SetMetadataIn(items, p, m)
}

func (pv *KeychainVault) SetMetadataIn(items []keychain.Item, p keychain.WebPassword, m Metadata) error {
	return pv.setMetadata(items, p, m, "SetMetadata")
}

func (pv *KeychainVault) SetTitleIn(items []keychain.Item, p keychain.WebPassword, title string) error {
	return pv.setMetadata(items, p, Metadata{Title: title, Note: p.Note, TOTP: p.TOTP}, "SetTitle")
}

func (pv *KeychainVault) setMetadata(items []keychain.Item, p keychain.WebPassword, m Metadata, what string) error {
	if p.IsDeleted {
		return fmt.Errorf("appleservices: %s: %q is deleted; restore it first", what, p.Domain)
	}
	var totp map[string]any
	if m.TOTP != "" {
		encoded, err := keychain.EncodeTOTPField(m.TOTP)
		if err != nil {
			return fmt.Errorf("appleservices: %w", err)
		}
		totp = encoded
	}

	i := companionIndex(items, p.Domain, p.Username)
	if i < 0 {
		inner := map[string]any{"s_as": []any{}}
		if !p.Website && p.Name != "" {
			inner["title"] = []byte(p.Name)
		}
		if !applyMetadata(inner, m, totp) {
			return nil
		}
		blob, err := keychain.EncodeCompanionItem(p.Domain, p.Username, inner)
		if err != nil {
			return fmt.Errorf("appleservices: %w", err)
		}
		if _, _, err := pv.v.AddItem("Passwords", blob); err != nil {
			return fmt.Errorf("appleservices: %s (create companion): %w", what, err)
		}
		return nil
	}

	inner := keychain.DecodeCompanionInner(items[i].Data)
	if inner == nil {
		inner = map[string]any{}
	}
	if !applyMetadata(inner, m, totp) {
		return nil
	}
	if err := pv.writeCompanion(items, i, p.Domain, p.Username, inner); err != nil {
		return fmt.Errorf("appleservices: %s: %w", what, err)
	}
	return nil
}

func applyMetadata(inner map[string]any, m Metadata, totp map[string]any) bool {
	title, note, otpauth := keychain.CompanionMetadata(inner)
	changed := false
	set := func(key, want, have string, value any) {
		if want == have {
			return
		}
		if want == "" {
			delete(inner, key)
		} else {
			inner[key] = value
		}
		changed = true
	}
	set("title", m.Title, title, []byte(m.Title))
	set("notes", m.Note, note, []byte(m.Note))
	set("totp", m.TOTP, otpauth, totp)
	return changed
}

func companionIndex(items []keychain.Item, srvr, acct string) int {
	for i, it := range items {
		if it.Agrp == "com.apple.password-manager" && it.Srvr == srvr && it.Acct == acct {
			return i
		}
	}
	return -1
}

func (pv *KeychainVault) writeCompanion(items []keychain.Item, i int, srvr, acct string, inner map[string]any) error {
	data, err := keychain.EncodeCompanionInner(inner)
	if err != nil {
		return err
	}
	blob, err := keychain.EncodeCompanionItem(srvr, acct, inner)
	if err != nil {
		return err
	}
	sr, err := pv.v.UpdateItem("Passwords", items[i].Name, items[i].Etag, blob)
	if err != nil {
		return err
	}
	items[i].Srvr = srvr
	items[i].Acct = acct
	items[i].Data = data
	items[i].Etag = sr.Etag
	return nil
}

type BulkResult[T any] struct {
	Entry T
	Err   error
}

func foldPurge(entries []keychain.WebPassword, owner []int, results []cloudkit.SaveResult) []BulkResult[keychain.WebPassword] {
	out := make([]BulkResult[keychain.WebPassword], len(entries))
	for i, e := range entries {
		out[i] = BulkResult[keychain.WebPassword]{Entry: e}
	}
	for j, sr := range results {
		i := owner[j]
		if out[i].Err != nil || sr.Code == 1 {
			continue
		}
		out[i].Err = &cloudkit.SaveError{SaveResult: sr}
	}
	return out
}

func (pv *KeychainVault) PurgeWebPasswords(ps []keychain.WebPassword) []BulkResult[keychain.WebPassword] {
	out := make([]BulkResult[keychain.WebPassword], len(ps))
	for i, p := range ps {
		out[i] = BulkResult[keychain.WebPassword]{Entry: p}
	}
	var refs []keychain.DeletedRef
	var owner []int
	for i, p := range ps {
		if !p.IsDeleted || len(p.Deleted) == 0 {
			out[i].Err = fmt.Errorf("appleservices: PurgeWebPasswords: %q is not a deleted entry", p.Domain)
			continue
		}
		for _, ref := range p.Deleted {
			refs = append(refs, ref)
			owner = append(owner, i)
		}
	}
	if len(refs) == 0 {
		return out
	}
	results, err := pv.v.DeleteRecords("Passwords", refs)
	if err != nil {
		for _, i := range owner {
			if out[i].Err == nil {
				out[i].Err = fmt.Errorf("appleservices: PurgeWebPasswords batch: %w", err)
			}
		}
		return out
	}
	folded := foldPurge(ps, owner, results)
	for i := range out {
		if out[i].Err == nil {
			out[i].Err = folded[i].Err
		}
	}
	return out
}

func (pv *KeychainVault) DeleteWebPasswords(ps []keychain.WebPassword) []BulkResult[keychain.WebPassword] {
	out, anyValid := deletableWebPasswords(ps)
	if !anyValid {
		return out
	}

	items, err := pv.v.Items("Passwords")
	if err != nil {
		for i := range out {
			if out[i].Err == nil {
				out[i].Err = fmt.Errorf("appleservices: DeleteWebPasswords: %w", err)
			}
		}
		return out
	}

	pv.moveWebPasswordsToDeleted(items, ps, out)
	return out
}

func (pv *KeychainVault) DeleteWebPasswordsIn(items []keychain.Item, ps []keychain.WebPassword) []BulkResult[keychain.WebPassword] {
	out, anyValid := deletableWebPasswords(ps)
	if !anyValid {
		return out
	}
	pv.moveWebPasswordsToDeleted(items, ps, out)
	return out
}

func deletableWebPasswords(ps []keychain.WebPassword) ([]BulkResult[keychain.WebPassword], bool) {
	out := make([]BulkResult[keychain.WebPassword], len(ps))
	anyValid := false
	for i, p := range ps {
		out[i] = BulkResult[keychain.WebPassword]{Entry: p}
		if p.IsDeleted {
			out[i].Err = fmt.Errorf("appleservices: DeleteWebPasswords: %q is already deleted", p.Domain)
			continue
		}
		anyValid = true
	}
	return out, anyValid
}

func (pv *KeychainVault) moveWebPasswordsToDeleted(items []keychain.Item, ps []keychain.WebPassword, out []BulkResult[keychain.WebPassword]) {
	for i, p := range ps {
		if out[i].Err != nil {
			continue
		}
		var recs []struct{ name, agrp string }
		for _, it := range items {
			if it.Srvr != p.Domain || it.Acct != p.Username {
				continue
			}
			if it.Agrp == "com.apple.cfnetwork" || it.Agrp == "com.apple.password-manager" {
				recs = append(recs, struct{ name, agrp string }{it.Name, it.Agrp})
			}
		}
		if len(recs) == 0 {
			out[i].Err = fmt.Errorf("appleservices: DeleteWebPasswords: no active records for %q (%s)", p.Domain, p.Username)
			continue
		}
		for _, r := range recs {
			if _, err := pv.v.MoveRecordIn("Passwords", items, r.name, r.agrp+"-recently-deleted"); err != nil {
				out[i].Err = fmt.Errorf("appleservices: DeleteWebPasswords (move %s): %w", r.name, err)
				break
			}
		}
	}
}

func (pv *KeychainVault) RestoreWebPassword(p keychain.WebPassword) error {
	if !p.IsDeleted || len(p.Deleted) == 0 {
		return fmt.Errorf("appleservices: RestoreWebPassword: %q is not a deleted entry", p.Domain)
	}
	cred, err := keychain.EncodeWebPasswordItem(p.Domain, p.Username, p.Password)
	if err != nil {
		return fmt.Errorf("appleservices: %w", err)
	}
	if err := pv.addRestoredItem(cred); err != nil {
		return fmt.Errorf("appleservices: restore web password (recreate credential): %w", err)
	}
	if p.Note != "" || (!p.Website && p.Name != "") {
		meta, err := keychain.EncodeMetadataItem(p.Domain, p.Username, p.Name, p.Note)
		if err != nil {
			return fmt.Errorf("appleservices: %w", err)
		}
		if err := pv.addRestoredItem(meta); err != nil {
			return fmt.Errorf("appleservices: restore web password (recreate metadata): %w", err)
		}
	}
	results, err := pv.v.DeleteRecords("Passwords", p.Deleted)
	if err != nil {
		return fmt.Errorf("appleservices: items restored but removing the recently-deleted records failed (retry RestoreWebPassword or PurgeWebPasswords to clear them): %w", err)
	}
	for i, sr := range results {
		if sr.Code != 1 {
			return fmt.Errorf("appleservices: items restored but removing a recently-deleted record (%s) failed (retry RestoreWebPassword or PurgeWebPasswords to clear it): %w", p.Deleted[i].RecordName, &cloudkit.SaveError{SaveResult: sr})
		}
	}
	return nil
}

func (pv *KeychainVault) addRestoredItem(attrs []byte) error {
	_, _, err := pv.v.AddItem("Passwords", attrs)
	if se, ok := errors.AsType[*cloudkit.SaveError](err); ok && se.AlreadyExists() {
		return nil
	}
	return err
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
