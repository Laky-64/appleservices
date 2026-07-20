package anisette

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Laky-64/http"
)

const DefaultServerListURL = "https://servers.sidestore.io/servers.json"

type Server struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

var fallbackServers = []Server{
	{Name: "SideStore (hardcoded fallback)", Address: "https://ani.sidestore.io"},
}

type serverListResponse struct {
	Servers []Server `json:"servers"`
}

type ServerList struct {
	cachePath string
	listURL   string
}

func NewServerList(cachePath, listURL string) *ServerList {
	return &ServerList{cachePath: cachePath, listURL: listURL}
}

func (l *ServerList) Servers() []Server {
	if servers, err := l.fetch(); err == nil && len(servers) > 0 {
		_ = l.writeCache(servers)
		return servers
	}
	if servers, err := l.readCache(); err == nil && len(servers) > 0 {
		return servers
	}
	return fallbackServers
}

func (l *ServerList) fetch() ([]Server, error) {
	result, err := http.ExecuteRequest(l.listURL, http.Timeout(10*time.Second))
	if err != nil {
		return nil, fmt.Errorf("anisette: fetch server list: %w", err)
	}
	if result.StatusCode != 200 {
		return nil, fmt.Errorf("anisette: server list status %d", result.StatusCode)
	}
	var parsed serverListResponse
	if err := json.Unmarshal(result.Body, &parsed); err != nil {
		return nil, fmt.Errorf("anisette: parse server list: %w", err)
	}
	if len(parsed.Servers) == 0 {
		return nil, errors.New("anisette: server list empty")
	}
	return parsed.Servers, nil
}

func (l *ServerList) writeCache(servers []Server) error {
	if l.cachePath == "" {
		return nil
	}
	data, err := json.Marshal(servers)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(l.cachePath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(l.cachePath, data, 0o600)
}

func (l *ServerList) readCache() ([]Server, error) {
	if l.cachePath == "" {
		return nil, errors.New("anisette: no cache path configured")
	}
	data, err := os.ReadFile(l.cachePath)
	if err != nil {
		return nil, err
	}
	var servers []Server
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, err
	}
	return servers, nil
}
