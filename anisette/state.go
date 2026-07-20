package anisette

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type State struct {
	Identifier []byte `json:"identifier"`
	AdiPB      []byte `json:"adi_pb,omitempty"`
}

func NewState() State {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		panic("anisette: crypto/rand failed: " + err.Error())
	}
	return State{Identifier: id}
}

func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewState(), nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, err
	}
	if len(s.Identifier) != 16 {
		return NewState(), nil
	}
	return s, nil
}

func (s State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (s State) DeviceID() string {
	u, _ := uuid.FromBytes(s.Identifier)
	return u.String()
}

func (s State) MDLU() string {
	sum := sha256.Sum256(s.Identifier)
	return hex.EncodeToString(sum[:])
}

func (s State) Provisioned() bool { return len(s.AdiPB) > 0 }

func DefaultStatePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "apple-passwords", "anisette", "state.json"), nil
}
