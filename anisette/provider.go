package anisette

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Laky-64/appleservices/gsa"
)

type Provider struct {
	statePath string
	servers   []string
	seeded    bool

	once  sync.Once
	setup error
	mu    sync.Mutex
	state State
	cli   *Client
}

var _ gsa.AnisetteProvider = (*Provider)(nil)

func NewProvider() gsa.AnisetteProvider {
	statePath, err := DefaultStatePath()
	if err != nil {
		return &Provider{setup: err}
	}
	return newProvider(statePath, defaultServers())
}

func defaultServers() []string {
	var urls []string
	for _, s := range NewServerList("", DefaultServerListURL).Servers() {
		urls = append(urls, s.Address)
	}
	return urls
}

func NewProviderFromState(state State, servers []string) *Provider {
	return &Provider{state: state, servers: servers, seeded: true}
}

func (p *Provider) State() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *Provider) saveState() error {
	if p.statePath == "" {
		return nil
	}
	return p.state.Save(p.statePath)
}

func newProvider(statePath string, servers []string) *Provider {
	return &Provider{statePath: statePath, servers: servers}
}

func (p *Provider) prepare() {
	if p.setup != nil {
		return
	}
	if p.seeded {
		if p.servers == nil {
			p.servers = defaultServers()
		}
	} else {
		state, err := LoadState(p.statePath)
		if err != nil {
			p.setup = err
			return
		}
		p.state = state
	}

	var lastErr error
	for _, url := range p.servers {
		cli, err := NewClient(url)
		if err != nil {
			lastErr = err
			continue
		}
		if !p.state.Provisioned() {
			if err := cli.Provision(context.Background(), &p.state); err != nil {
				lastErr = err
				continue
			}
			if err := p.saveState(); err != nil {
				p.setup = err
				return
			}
		}
		p.cli = cli
		return
	}
	p.setup = fmt.Errorf("anisette: no server usable: %w", lastErr)
}

func (p *Provider) Headers() (map[string]string, error) {
	p.once.Do(p.prepare)
	if p.setup != nil {
		return nil, p.setup
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	if p.cli != nil {
		if h, err := p.headersVia(p.cli); err == nil {
			return h, nil
		} else {
			lastErr = err
		}
	}
	for _, url := range p.servers {
		if p.cli != nil && url == p.cli.url {
			continue
		}
		cli, err := NewClient(url)
		if err != nil {
			lastErr = err
			continue
		}
		if h, err := p.headersVia(cli); err == nil {
			p.cli = cli
			return h, nil
		} else {
			lastErr = err
		}
	}
	return nil, fmt.Errorf("anisette: all servers failed: %w", lastErr)
}

func (p *Provider) headersVia(cli *Client) (map[string]string, error) {
	h, err := cli.GetHeaders(p.state)
	if errors.Is(err, errNotProvisioned) {
		p.state.AdiPB = nil
		if perr := cli.Provision(context.Background(), &p.state); perr != nil {
			return nil, perr
		}
		if serr := p.saveState(); serr != nil {
			return nil, serr
		}
		return cli.GetHeaders(p.state)
	}
	return h, err
}
