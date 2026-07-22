package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Laky-64/appleservices"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "passwords: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	appleID := flag.String("appleid", os.Getenv("APPLESERVICES_APPLEID"), "Apple ID email (or APPLESERVICES_APPLEID)")
	password := flag.String("password", os.Getenv("APPLESERVICES_PASSWORD"), "Apple ID password (or APPLESERVICES_PASSWORD)")
	passcode := flag.String("passcode", os.Getenv("APPLESERVICES_PASSCODE"), "device passcode unlocking the iCloud escrow record (or APPLESERVICES_PASSCODE)")
	dir := flag.String("dir", os.Getenv("APPLESERVICES_DIR"), "directory for cached device identity + session state (or APPLESERVICES_DIR)")
	flag.Parse()

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

	login, err := appleservices.BeginLogin(creds, store)
	if err != nil {
		return fmt.Errorf("begin login: %w", err)
	}

	if login.NeedsTwoFactor() {
		fmt.Fprintln(os.Stderr, "Two-factor authentication required; requesting a trusted-device code ...")
		if err := login.RequestCode(); err != nil {
			return fmt.Errorf("request code: %w", err)
		}
		code, err := promptCode()
		if err != nil {
			return err
		}
		if err := login.SubmitCode(code); err != nil {
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

	pv, err := client.OpenPasswordsWith(chosen, *passcode)
	if err != nil {
		return fmt.Errorf("open passwords: %w", err)
	}
	pws, err := pv.WebPasswords()
	if err != nil {
		return fmt.Errorf("web passwords: %w", err)
	}

	for _, pw := range pws {
		kind := "manual"
		if pw.Website {
			kind = "web"
		}
		fmt.Printf("[%s] %s\t%s\t%s\t%s", kind, pw.Name, pw.Domain, pw.Username, pw.Password)
		if code, err := pw.TOTPCode(time.Now()); err == nil {
			fmt.Printf("\tTOTP=%s", code)
		}
		fmt.Println()
	}
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
