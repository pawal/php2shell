package probe

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/pawal/php2shell/engine/verdict"
)

// TestLab checks the containers of lab/docker-compose.yml; make test-lab
// starts them and sets PHP2SHELL_LAB.
func TestLab(t *testing.T) {
	if os.Getenv("PHP2SHELL_LAB") == "" {
		t.Skip("PHP2SHELL_LAB is not set")
	}
	cases := []struct {
		port   string
		oracle bool
		want   string
	}{
		{"18081", true, verdict.LikelyVulnerable},
		{"18081", false, verdict.LikelyVulnerable},
		{"18082", true, verdict.LikelyPatched},
		{"18082", false, verdict.LikelyPatched},
		{"18083", true, verdict.NoPHPSignal},
		{"18084", true, verdict.NoPHPSignal},
	}
	p := &Prober{AllowNonGlobal: true}
	for _, c := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		in, _, err := p.Check(ctx, Target{Scheme: "http", Host: "127.0.0.1", Port: c.port, Path: "/"}, c.oracle)
		cancel()
		if err != nil {
			t.Errorf(":%s oracle=%v: %v", c.port, c.oracle, err)
			continue
		}
		if got := verdict.Judge(in).Verdict; got != c.want {
			t.Errorf(":%s oracle=%v: got %s, want %s", c.port, c.oracle, got, c.want)
		}
	}
	strict := &Prober{}
	if _, _, err := strict.Check(context.Background(), Target{Scheme: "http", Host: "127.0.0.1", Port: "18081", Path: "/"}, true); err == nil {
		t.Error("the default policy reached the lab")
	}
}

// TestLive runs the lab's expectations against public instances of our own,
// under the default policy. make test-live names them in PHP2SHELL_LIVE_*.
func TestLive(t *testing.T) {
	cases := []struct {
		env    string
		want   string
		oracle bool
	}{
		{"PHP2SHELL_LIVE_UNPATCHED", verdict.LikelyVulnerable, true},
		{"PHP2SHELL_LIVE_PATCHED", verdict.LikelyPatched, true},
		{"PHP2SHELL_LIVE_STATIC", verdict.NoPHPSignal, true},
	}
	ran := false
	for _, c := range cases {
		address := os.Getenv(c.env)
		if address == "" {
			continue
		}
		ran = true
		target, err := ParseTarget(address)
		if err != nil {
			t.Errorf("%s=%q: %v", c.env, address, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		in, evidence, err := (&Prober{}).Check(ctx, target, c.oracle)
		cancel()
		if err != nil {
			t.Errorf("%s: %v", c.env, err)
			continue
		}
		if got := verdict.Judge(in).Verdict; got != c.want {
			t.Errorf("%s: got %s, want %s; evidence %+v", c.env, got, c.want, evidence)
		}
	}
	if !ran {
		t.Skip("no PHP2SHELL_LIVE_* variable is set")
	}
}
