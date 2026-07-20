package icloud

import "errors"

func PETFromSPD(spd map[string]any) (string, error) {
	t, ok := spd["t"].(map[string]any)
	if !ok {
		return "", errors.New("icloud: spd has no token map (t)")
	}
	pet, ok := t["com.apple.gs.idms.pet"].(map[string]any)
	if !ok {
		return "", errors.New("icloud: spd token map has no com.apple.gs.idms.pet entry")
	}
	token, ok := pet["token"].(string)
	if !ok || token == "" {
		return "", errors.New("icloud: com.apple.gs.idms.pet has no token string")
	}
	return token, nil
}
