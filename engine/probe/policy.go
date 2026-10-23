package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Ports a public website is checked on.
var publicPorts = map[string]bool{"80": true, "443": true, "8080": true, "8443": true}

// PolicyError is a target the address policy declines; no request was sent.
type PolicyError struct {
	Host   string
	Reason string
	Addr   string // the refused address the host resolved to, if any
}

func (e *PolicyError) Error() string {
	if e.Addr != "" {
		return fmt.Sprintf("%s is not a public website: %s is %s", e.Host, e.Addr, e.Reason)
	}
	return fmt.Sprintf("%s is not a public website: %s", e.Host, e.Reason)
}

// Public is the refusal without the resolved address, which would show strangers how this server resolves names.
func (e *PolicyError) Public() string {
	if e.Addr != "" {
		return fmt.Sprintf("%s is not a public website: it resolves to a non-public address (%s)", e.Host, e.Reason)
	}
	return e.Error()
}

// ErrUnresolvable is a host name with no address.
var ErrUnresolvable = errors.New("the host name does not resolve")

// Resolver is the lookup the policy validates; *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// pins holds the validated addresses of every host one check has resolved,
// so each host is looked up once and only those addresses are dialled.
type pins struct {
	resolver       Resolver
	allowNonGlobal bool

	mu    sync.Mutex
	hosts map[string][]netip.Addr
}

func newPins(resolver Resolver, allowNonGlobal bool) *pins {
	return &pins{resolver: resolver, allowNonGlobal: allowNonGlobal, hosts: map[string][]netip.Addr{}}
}

// admitPort declines a port no public website is served on.
func (p *pins) admitPort(host, port string) error {
	if p.allowNonGlobal || publicPorts[port] {
		return nil
	}
	return &PolicyError{Host: host, Reason: "port " + port + " is not 80, 443, 8080 or 8443"}
}

// addresses resolves and validates a host once per check; every address of
// the answer must be global, or the host is declined.
func (p *pins) addresses(ctx context.Context, host string) ([]netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if addrs, ok := p.hosts[host]; ok {
		return addrs, nil
	}
	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
	} else {
		found, err := p.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(found) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnresolvable, host)
		}
		addrs = found
	}
	if !p.allowNonGlobal {
		for _, addr := range addrs {
			if reason := NotGlobalReason(addr); reason != "" {
				return nil, &PolicyError{Host: host, Reason: reason, Addr: addr.String()}
			}
		}
	}
	p.hosts[host] = addrs
	return addrs, nil
}

// dial connects to the pinned addresses of a host in turn.
func (p *pins) dial(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if err := p.admitPort(host, port); err != nil {
			return nil, err
		}
		addrs, err := p.addresses(ctx, host)
		if err != nil {
			return nil, err
		}
		var last error
		for _, addr := range addrs {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}
