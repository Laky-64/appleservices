package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Laky-64/appleservices"
)

type fileStore struct {
	dir string
}

func (s fileStore) devicePath() string  { return filepath.Join(s.dir, "device.json") }
func (s fileStore) sessionPath() string { return filepath.Join(s.dir, "session.json") }

func (s fileStore) LoadDevice() (*appleservices.Device, error) {
	data, err := os.ReadFile(s.devicePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var dev appleservices.Device
	if err := json.Unmarshal(data, &dev); err != nil {
		return nil, err
	}
	return &dev, nil
}

func (s fileStore) SaveDevice(dev *appleservices.Device) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(dev)
	if err != nil {
		return err
	}
	return os.WriteFile(s.devicePath(), data, 0o600)
}

func (s fileStore) LoadSession() (*appleservices.Session, error) {
	data, err := os.ReadFile(s.sessionPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var sess appleservices.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s fileStore) SaveSession(sess *appleservices.Session) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return os.WriteFile(s.sessionPath(), data, 0o600)
}
