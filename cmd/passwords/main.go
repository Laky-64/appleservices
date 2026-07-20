package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
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

	pws, err := client.WebPasswords(*passcode)
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
