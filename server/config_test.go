package server

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfigValidates(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
}

// A flag beats the environment, which beats the file, which beats the default.
func TestConfigLayering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen_addr":"127.0.0.1:1","target_cooldown":"1m","rate_limit":{"enabled":true,"max":3,"window":"1h"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PHP2SHELL_TARGET_COOLDOWN": "2m", "PHP2SHELL_RATE_LIMIT_MAX": "7", "PHP2SHELL_MAX_CONCURRENT_CHECKS": "x"}
	cfg, _, err := LoadConfig([]string{"-config", path, "-rate-limit-max", "9"}, func(k string) string { return env[k] }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:1" || cfg.TargetCooldown.Duration != 2*time.Minute || cfg.RateLimit.Max != 9 || cfg.MaxConcurrentChecks != 10 {
		t.Errorf("layering: %+v", cfg)
	}
}

func TestConfigRefusals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen_adr":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	if cfg.ApplyFile(path) == nil {
		t.Error("an unknown key was accepted")
	}
	bad := DefaultConfig()
	bad.PublicURL = "https://example.net/path"
	bad.MaxConcurrentChecks = 0
	bad.TrustedProxyCIDRs = []string{"nope"}
	if bad.Validate() == nil {
		t.Error("a faulty configuration validated")
	}
}
