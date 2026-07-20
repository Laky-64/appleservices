# appleservices

A Go library for Apple's private iCloud / keychain services. It signs in to an
Apple ID, joins the account's trust circle, and **decrypts your synced Passwords
in clear text** — no Apple device, no Wine, no browser automation.

```go
login, _  := appleservices.BeginLogin(creds, store) // sign in (handle 2FA once)
client, _ := login.Client()
pws, _    := client.WebPasswords(passcode)          // decrypt
for _, p := range pws {
    fmt.Println(p.Name, p.Domain, p.Username, p.Password, p.TOTP)
}
```

> ⚠️ **Use it only on an Apple ID you own.** This is an unofficial, clean-room
> reimplementation of Apple's private protocols (GrandSlam auth, CloudKit/CKKS,
> Octagon). It exists for personal data access and research. Nothing here talks
> to a service on your behalf beyond what you'd do signing in yourself.

## Install

```sh
go get github.com/Laky-64/appleservices
```

Pure Go. The only runtime dependency is an [anisette](https://github.com/SideStore/anisette-server-list)
server for device-identity headers — the library uses the public pool by default.

## Quick start

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Laky-64/appleservices"
)

func main() {
	creds := appleservices.Credentials{AppleID: "you@icloud.com", Password: "…"}
	store := &fileStore{dir: "./state"} // your Store (see below)

	login, err := appleservices.BeginLogin(creds, store)
	if err != nil {
		panic(err)
	}

	// First run needs a trusted-device code; later runs skip it.
	if login.NeedsTwoFactor() {
		login.RequestCode() // pushes a code to your trusted Apple devices
		fmt.Print("code: ")
		code, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		login.SubmitCode(strings.TrimSpace(code))
	}

	client, _ := login.Client()

	pws, _ := client.WebPasswords("123456") // your device passcode
	for _, p := range pws {
		fmt.Printf("%-20s %-25s %s\n", p.Name, p.Username, p.Password)
	}
}
```

A complete runnable example (with a file-backed `Store`) lives in
[`cmd/passwords`](cmd/passwords).

## What you get

`WebPasswords` returns your Safari/AutoFill entries:

```go
type WebPassword struct {
	Name     string    // display title, e.g. "Photon Engine" or "uwu"
	Domain   string    // site host (or an opaque id for a manual entry)
	Website  bool      // true = website login, false = manually-added entry
	Username string
	Password string
	TOTP     string    // otpauth:// URL, if the entry has a verification code
	Created  time.Time
	Modified time.Time
}
```

Need the current 6-digit 2FA code? It's built in (RFC 6238):

```go
code, err := p.TOTPCode(time.Now()) // "773933"
```

## The Store (required)

The library never touches disk itself — you decide where its two pieces of state
live (a stable anisette **device identity**, and the GSA **trusted session** that
lets later logins skip 2FA). Implement this tiny interface with files, a DB, an OS
keychain, whatever:

```go
type Store interface {
	LoadDevice() (*Device, error);  SaveDevice(*Device) error
	LoadSession() (*Session, error); SaveSession(*Session) error
}

type Device  struct { Identifier, ProvisioningBlob []byte }
type Session struct { DSID string; Cookies []Cookie }
type Cookie  struct { URL, Name, Value string }
```

A trivial file backend (JSON, 0600) — see `cmd/passwords/filestore.go`:

```go
func (s fileStore) SaveDevice(d *appleservices.Device) error {
	b, _ := json.Marshal(d)
	return os.WriteFile(filepath.Join(s.dir, "device.json"), b, 0o600)
}
```

## Notes

- **Two-factor is trusted-device only** (never SMS): SMS 2FA does not grant the
  Octagon trust needed to read the keychain, so the API doesn't offer it.
- **Apple ID + password are needed on every run.** The stored session only skips
  the 2FA *code prompt* — the password itself can't be avoided (both the GrandSlam
  login and the escrow recovery authenticate with it). Persist it in your own app
  behind a local unlock if you want convenience; the library won't store it for you.
- The **device passcode** is what recovers the account's escrow key. It's passed
  per call and never stored.

## How it works

`BeginLogin`/`Client` → GrandSlam login (`gsa`) + anisette (`anisette`) + iCloud
tokens (`icloud`) + CloudKit bootstrap (`cloudkit`). `Vault` → escrow SRP recovery (`escrow`) →
Octagon bottle decrypt (`octagon`) → the sponsor peer keys → fetch the CKKS
`Passwords` zone and unwrap its keys/items (`ckks`) → clear-text keychain items
(`keychain`).

The library is layered: import a single stage (e.g. `gsa`, `ckks`) directly, or
use the `appleservices` facade shown above.

## Status

Recovers **web passwords** (and their titles + TOTP codes) end-to-end. WiFi
passwords, credit cards, passkeys and other keychain classes decrypt through the
same `ckks` path and are a small decoder away.

## License

[MIT](LICENSE). No warranty. Not affiliated with Apple — use it on accounts you own.
