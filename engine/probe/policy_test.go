package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
)

// fakeResolver answers from a table and counts lookups.
type fakeResolver struct {
	answers map[string][]string
	calls   atomic.Int32
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	var out []netip.Addr
	for _, a := range f.answers[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

func target(host, port string) Target {
	return Target{Scheme: "https", Host: host, Port: port, Path: "/"}
}

func TestCheckAppliesThePolicy(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]string{
		"public.example.com":  {"93.184.215.14", "2606:4700::1"},
		"private.example.com": {"10.0.0.7"},
		"mixed.example.com":   {"93.184.215.14", "127.0.0.1"},
		"mapped.example.com":  {"::ffff:93.184.215.14"},
		"nat64.example.com":   {"64:ff9b::5db8:d70e"},
	}}
	p := &Prober{Resolver: resolver}
	ctx := context.Background()

	for _, host := range []string{"private.example.com", "mixed.example.com", "mapped.example.com", "nat64.example.com", "127.0.0.1", "::ffff:10.0.0.1"} {
		var policy *PolicyError
		if _, _, err := p.Check(ctx, target(host, "443"), true); !errors.As(err, &policy) {
			t.Errorf("%s: got %v, want a policy refusal", host, err)
		}
	}
	var policy *PolicyError
	if _, _, err := p.Check(ctx, target("public.example.com", "22"), false); !errors.As(err, &policy) {
		t.Errorf("port 22: got %v, want a policy refusal", err)
	}
	if _, _, err := p.Check(ctx, target("missing.example.com", "443"), false); !errors.Is(err, ErrUnresolvable) {
		t.Errorf("missing name: got %v", err)
	}
	if err := newPins(resolver, false).admitPort("public.example.com", "443"); err != nil {
		t.Errorf("public port: %v", err)
	}
	lab := newPins(resolver, true)
	if err := lab.admitPort("private.example.com", "18081"); err != nil {
		t.Fatal(err)
	}
	if _, err := lab.addresses(ctx, "private.example.com"); err != nil {
		t.Fatal(err)
	}

}

// A host is resolved once per check, so a second answer cannot move the dial.
func TestPinsResolveOnce(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]string{"public.example.com": {"93.184.215.14"}}}
	pinned := newPins(resolver, false)
	for range 3 {
		if _, err := pinned.addresses(context.Background(), "public.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if resolver.calls.Load() != 1 {
		t.Errorf("resolved %d times", resolver.calls.Load())
	}
}

func TestSameSite(t *testing.T) {
	for _, pair := range [][2]string{{"example.com", "www.example.com"}, {"www.example.com", "example.com"}, {"a.example.com", "a.example.com"}} {
		if !sameSite(pair[0], pair[1]) {
			t.Errorf("%s to %s refused", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"example.com", "example.net"}, {"example.com", "badexample.com"}, {"example.com", "com"}, {"93.184.215.14", "example.com"}} {
		if sameSite(pair[0], pair[1]) {
			t.Errorf("%s to %s admitted", pair[0], pair[1])
		}
	}
}
