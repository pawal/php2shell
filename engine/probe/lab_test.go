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
		{"18081", true, verdict.Vulnerable},
		{"18081", false, verdict.LikelyVulnerable},
		{"18082", true, verdict.Patched},
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
