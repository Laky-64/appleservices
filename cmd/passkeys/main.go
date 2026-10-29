package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/anisette"
	"github.com/Laky-64/appleservices/keychain"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "passkeys: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	appleID := flag.String("appleid", os.Getenv("APPLESERVICES_APPLEID"), "Apple ID email (or APPLESERVICES_APPLEID)")
	password := flag.String("password", os.Getenv("APPLESERVICES_PASSWORD"), "Apple ID password (or APPLESERVICES_PASSWORD)")
	passcode := flag.String("passcode", os.Getenv("APPLESERVICES_PASSCODE"), "device passcode unlocking the iCloud escrow record (or APPLESERVICES_PASSCODE)")
	dir := flag.String("dir", os.Getenv("APPLESERVICES_DIR"), "directory for cached device identity + session state (or APPLESERVICES_DIR)")
	server := flag.String("anisette", os.Getenv("APPLESERVICES_ANISETTE"), "anisette server URL (or APPLESERVICES_ANISETTE)")
	flag.Parse()
	command := flag.Arg(0)
	if command != "attrs" && command != "add-test" && command != "purge-test" && command != "inspect-test" && command != "edit-test" {
		return fmt.Errorf("usage: passkeys [flags] attrs|add-test|purge-test|inspect-test|edit-test")
	}

	if *appleID == "" || *password == "" {
		return fmt.Errorf("appleid and password are required (flags -appleid/-password or APPLESERVICES_APPLEID/APPLESERVICES_PASSWORD)")
	}
	if *passcode == "" {
		return fmt.Errorf("passcode is required (flag -passcode or APPLESERVICES_PASSCODE)")
	}
	if *dir == "" {
		return fmt.Errorf("dir is required (flag -dir or APPLESERVICES_DIR)")
	}

	store := fileStore{dir: *dir}
	creds := appleservices.Credentials{AppleID: *appleID, Password: *password}

	var opts []appleservices.Option
	var provider *anisette.Provider
	if *server != "" {
		dev, err := store.LoadDevice()
		if err != nil {
			return fmt.Errorf("load device: %w", err)
		}
		state := anisette.NewState()
		if dev != nil && len(dev.Identifier) == 16 {
			state = anisette.State{Identifier: dev.Identifier, AdiPB: dev.ProvisioningBlob}
		}
		provider = anisette.NewProviderFromState(state, []string{*server})
		opts = append(opts, appleservices.WithAnisette(provider))
	}
	login, err := appleservices.BeginLogin(creds, store, opts...)
	if err != nil {
		return fmt.Errorf("begin login: %w", err)
	}

	if provider != nil {
		if kept := provider.State(); len(kept.Identifier) != 0 {
			if err := store.SaveDevice(&appleservices.Device{Identifier: kept.Identifier, ProvisioningBlob: kept.AdiPB}); err != nil {
				return fmt.Errorf("save device: %w", err)
			}
		}
	}

	if login.NeedsTwoFactor() {
		fmt.Fprintln(os.Stderr, "Two-factor authentication required; requesting a trusted-device code ...")
		if err := login.RequestCode(appleservices.TrustedDevice); err != nil {
			return fmt.Errorf("request code: %w", err)
		}
		code, err := promptCode()
		if err != nil {
			return err
		}
		if err := login.SubmitCode(appleservices.TrustedDevice, code); err != nil {
			return fmt.Errorf("submit code: %w", err)
		}
	}

	client, err := login.Client()
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}

	refs, err := client.ViableBottles()
	if err != nil {
		return fmt.Errorf("viable bottles: %w", err)
	}
	if len(refs) == 0 {
		return fmt.Errorf("no recoverable bottles for this account")
	}
	chosen := refs[0]
	if len(refs) > 1 {
		fmt.Fprintln(os.Stderr, "Multiple recoverable devices — the passcode must belong to the one you pick:")
		for i, r := range refs {
			fmt.Fprintf(os.Stderr, "  [%d] %s %s (serial %s, build %s)\n", i, r.Device.Model, r.Device.Name, r.Device.Serial, r.Device.Build)
		}
		idx, err := promptIndex(len(refs))
		if err != nil {
			return err
		}
		chosen = refs[idx]
	}
	fmt.Fprintf(os.Stderr, "Recovering via device: %s %s (serial %s, build %s)\n",
		chosen.Device.Model, chosen.Device.Name, chosen.Device.Serial, chosen.Device.Build)

	kc, err := client.OpenKeychain(chosen, *passcode)
	if err != nil {
		return fmt.Errorf("open keychain: %w", err)
	}
	switch command {
	case "add-test":
		return addTest(kc)
	case "purge-test":
		return purgeTest(kc)
	case "inspect-test":
		return inspectTest(kc)
	case "edit-test":
		return editTest(kc)
	}
	items, err := kc.Items()
	if err != nil {
		return fmt.Errorf("items: %w", err)
	}
	n := 0
	for _, it := range items {
		if it.Class != "keys" || it.Agrp != "com.apple.webkit.webauthn" {
			continue
		}
		n++
		fmt.Printf("item %d\n", n)
		fmt.Println("  " + keyLabelRelations(it.Attrs))
		for _, line := range describeAttrs(it.Attrs) {
			fmt.Println("  " + line)
		}
	}
	fmt.Fprintf(os.Stderr, "%d passkey items\n", n)
	return nil
}

func promptIndex(n int) (int, error) {
	fmt.Fprintf(os.Stderr, "Enter device number [0-%d]: ", n-1)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read selection: %w", err)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || idx < 0 || idx >= n {
		return 0, fmt.Errorf("invalid selection %q", strings.TrimSpace(line))
	}
	return idx, nil
}

func promptCode() (string, error) {
	fmt.Fprint(os.Stderr, "Enter the verification code: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read code: %w", err)
	}
	code := strings.TrimSpace(line)
	if code == "" {
		return "", fmt.Errorf("no code entered")
	}
	return code, nil
}

const testRelyingParty = "renvault-test.invalid"

func addTest(kc *appleservices.KeychainVault) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return err
	}
	id := sha1.Sum(pub)
	handle := make([]byte, 16)
	if _, err := rand.Read(handle); err != nil {
		return err
	}
	now := time.Now().UTC()
	pk := keychain.Passkey{
		RelyingParty: testRelyingParty,
		UserName:     "renvault-test",
		DisplayName:  "RenVault Test",
		CredentialID: id[:],
		UserHandle:   handle,
		PrivateKey:   key,
		Created:      now,
		Modified:     now,
	}
	if err := kc.AddPasskey(pk); err != nil {
		return err
	}
	fmt.Printf("added %s credential %x\n", testRelyingParty, id[:])
	return nil
}

func purgeTest(kc *appleservices.KeychainVault) error {
	all, err := kc.Passkeys()
	if err != nil {
		return err
	}
	var active []keychain.Passkey
	for _, pk := range all {
		if pk.RelyingParty == testRelyingParty && !pk.IsDeleted {
			active = append(active, pk)
		}
	}
	for _, r := range kc.DeletePasskeys(active) {
		if r.Err != nil {
			return r.Err
		}
	}
	all, err = kc.Passkeys()
	if err != nil {
		return err
	}
	var deleted []keychain.Passkey
	for _, pk := range all {
		if pk.RelyingParty == testRelyingParty && pk.IsDeleted {
			deleted = append(deleted, pk)
		}
	}
	for _, r := range kc.PurgePasskeys(deleted) {
		if r.Err != nil {
			return r.Err
		}
	}
	fmt.Printf("purged %d %s passkeys\n", len(deleted), testRelyingParty)
	return nil
}

func editTest(kc *appleservices.KeychainVault) error {
	all, err := kc.Passkeys()
	if err != nil {
		return err
	}
	for _, pk := range all {
		if pk.RelyingParty != testRelyingParty || pk.IsDeleted {
			continue
		}
		if err := kc.EditPasskey(pk, "renvault-edit2", "renvault nota da RenVault 2"); err != nil {
			return err
		}
		fmt.Printf("edited %s %s\n", testRelyingParty, pk.UserName)
	}
	return nil
}
