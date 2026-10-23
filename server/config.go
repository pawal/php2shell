package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// envPrefix namespaces every environment override.
const envPrefix = "PHP2SHELL_"

// Duration is a time.Duration written as a string.
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	return d.Set(text)
}

// Set implements flag.Value.
func (d *Duration) Set(text string) error {
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

// RateLimitConfig bounds checks per client address.
type RateLimitConfig struct {
	Enabled bool     `json:"enabled"`
	Max     int      `json:"max"`
	Window  Duration `json:"window"`
}

// Config is the service's whole configuration.
type Config struct {
	ListenAddr string `json:"listen_addr"`
	// PublicURL is the origin the canonical links and the sitemap name.
	PublicURL   string `json:"public_url,omitempty"`
	Provider    string `json:"provider"`
	ProviderURL string `json:"provider_url"`
	SourceURL   string `json:"source_url"`
	// Contact is shown on the about page for opt-out requests.
	Contact             string          `json:"contact,omitempty"`
	TrustedProxyCIDRs   []string        `json:"trusted_proxy_cidrs,omitempty"`
	SourceAddresses     []string        `json:"source_addresses,omitempty"` // shown on the about page
	RateLimit           RateLimitConfig `json:"rate_limit"`
	TargetCooldown      Duration        `json:"target_cooldown"`
	MaxConcurrentChecks int             `json:"max_concurrent_checks"`
	CheckTimeout        Duration        `json:"check_timeout"`
	// LogFile receives one line per check; empty logs nothing.
	LogFile         string `json:"log_file,omitempty"`
	FingerprintFile string `json:"fingerprint_file,omitempty"`
	// AllowNonGlobalAddresses lifts the address and port policy, for a lab.
	AllowNonGlobalAddresses bool     `json:"allow_non_global_addresses,omitempty"`
	MaxBodySize             int64    `json:"max_body_size"`
	ReadTimeout             Duration `json:"read_timeout"`
	WriteTimeout            Duration `json:"write_timeout"`
	IdleTimeout             Duration `json:"idle_timeout"`
}

// DefaultConfig is the baseline a file, the environment and flags refine.
func DefaultConfig() Config {
	return Config{
		ListenAddr:          "127.0.0.1:8080",
		Provider:            "evilbit.de",
		ProviderURL:         "https://evilbit.de/",
		SourceURL:           "https://github.com/pawal/php2shell",
		RateLimit:           RateLimitConfig{Enabled: true, Max: 10, Window: Duration{time.Hour}},
		TargetCooldown:      Duration{5 * time.Minute},
		MaxConcurrentChecks: 10,
		CheckTimeout:        Duration{15 * time.Second},
		MaxBodySize:         4 << 10,
		ReadTimeout:         Duration{10 * time.Second},
		WriteTimeout:        Duration{30 * time.Second},
		IdleTimeout:         Duration{60 * time.Second},
	}
}

// key binds one field to its flag and environment variable.
type key[T any] struct {
	flag  string
	env   string
	usage string
	ptr   func(*Config) *T
}

var stringKeys = []key[string]{
	{"listen", "LISTEN", "address to listen on", func(c *Config) *string { return &c.ListenAddr }},
	{"public-url", "PUBLIC_URL", "origin the canonical links and the sitemap name", func(c *Config) *string { return &c.PublicURL }},
	{"provider", "PROVIDER", "who provides the service, shown in the footer", func(c *Config) *string { return &c.Provider }},
	{"provider-url", "PROVIDER_URL", "where the footer's provider links to", func(c *Config) *string { return &c.ProviderURL }},
	{"source-url", "SOURCE_URL", "where the source code is published", func(c *Config) *string { return &c.SourceURL }},
	{"contact", "CONTACT", "address for opt-out requests, shown on the about page", func(c *Config) *string { return &c.Contact }},
	{"log-file", "LOG_FILE", "file receiving one line per check, empty for none", func(c *Config) *string { return &c.LogFile }},
	{"fingerprints", "FINGERPRINT_FILE", "PHP fingerprint database; empty loads the default if present", func(c *Config) *string { return &c.FingerprintFile }},
}

var intKeys = []key[int]{
	{"rate-limit-max", "RATE_LIMIT_MAX", "checks allowed per window per client", func(c *Config) *int { return &c.RateLimit.Max }},
	{"max-concurrent-checks", "MAX_CONCURRENT_CHECKS", "checks in flight at once", func(c *Config) *int { return &c.MaxConcurrentChecks }},
}

var int64Keys = []key[int64]{
	{"max-body-size", "MAX_BODY_SIZE", "largest accepted request body", func(c *Config) *int64 { return &c.MaxBodySize }},
}

var boolKeys = []key[bool]{
	{"rate-limit", "RATE_LIMIT", "rate limit checks per client address", func(c *Config) *bool { return &c.RateLimit.Enabled }},
	{"allow-non-global", "ALLOW_NON_GLOBAL_ADDRESSES", "check non-global addresses and any port, for a lab", func(c *Config) *bool { return &c.AllowNonGlobalAddresses }},
}

var durationKeys = []key[Duration]{
	{"rate-limit-window", "RATE_LIMIT_WINDOW", "sliding window the check limit counts over", func(c *Config) *Duration { return &c.RateLimit.Window }},
	{"target-cooldown", "TARGET_COOLDOWN", "age at which a cached result stops answering for its host", func(c *Config) *Duration { return &c.TargetCooldown }},
	{"check-timeout", "CHECK_TIMEOUT", "wall clock one check may take", func(c *Config) *Duration { return &c.CheckTimeout }},
	{"read-timeout", "READ_TIMEOUT", "request read timeout", func(c *Config) *Duration { return &c.ReadTimeout }},
	{"write-timeout", "WRITE_TIMEOUT", "response write timeout", func(c *Config) *Duration { return &c.WriteTimeout }},
	{"idle-timeout", "IDLE_TIMEOUT", "keep-alive idle timeout", func(c *Config) *Duration { return &c.IdleTimeout }},
}

var listKeys = []key[[]string]{
	{"trusted-proxy-cidrs", "TRUSTED_PROXY_CIDRS", "sources whose forwarded client address is honoured", func(c *Config) *[]string { return &c.TrustedProxyCIDRs }},
	{"source-addresses", "SOURCE_ADDRESSES", "addresses checks are sent from, shown on the about page", func(c *Config) *[]string { return &c.SourceAddresses }},
}

// commaList binds a comma-separated value to a slice.
type commaList struct{ dst *[]string }

func (c commaList) String() string {
	if c.dst == nil {
		return ""
	}
	return strings.Join(*c.dst, ",")
}

func (c commaList) Set(text string) error {
	*c.dst = splitList(text)
	return nil
}

func splitList(text string) []string {
	var out []string
	for field := range strings.SplitSeq(text, ",") {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out
}

// Startup is what the command line asked for beyond the configuration.
type Startup struct {
	ConfigPath string
	DumpConfig bool
}

// FlagUsage lists every configuration flag with its default.
func FlagUsage() string {
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfg := DefaultConfig()
	bindFlags(set, &cfg)
	var buf bytes.Buffer
	set.SetOutput(&buf)
	set.PrintDefaults()
	return buf.String()
}

// LoadConfig layers defaults, the named file, the environment and flags. A
// malformed environment value is reported to warn and ignored.
func LoadConfig(args []string, getenv func(string) string, warn io.Writer) (Config, Startup, error) {
	var startup Startup
	over := DefaultConfig()
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&startup.ConfigPath, "config", "", "read configuration from this file")
	set.BoolVar(&startup.DumpConfig, "dump-config", false, "print the effective configuration and exit")
	bindFlags(set, &over)
	if err := set.Parse(args); err != nil {
		return Config{}, startup, err
	}
	if set.NArg() > 0 {
		return Config{}, startup, fmt.Errorf("unexpected argument %q", set.Arg(0))
	}
	flagsSet := map[string]bool{}
	set.Visit(func(f *flag.Flag) { flagsSet[f.Name] = true })

	cfg := DefaultConfig()
	if startup.ConfigPath != "" {
		if err := cfg.ApplyFile(startup.ConfigPath); err != nil {
			return Config{}, startup, err
		}
	}
	applyEnv(&cfg, flagsSet, getenv, warn)
	applyFlags(&cfg, flagsSet, &over)
	return cfg, startup, nil
}

// ApplyFile overlays a JSON file; an absent key keeps its value and an
// unknown key is refused.
func (c *Config) ApplyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(c); err != nil {
		return fmt.Errorf("parse configuration %s: %w", path, err)
	}
	return nil
}

// Dump writes the configuration as a file an operator can reuse.
func (c Config) Dump(w io.Writer) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func bindFlags(set *flag.FlagSet, over *Config) {
	for _, k := range stringKeys {
		set.StringVar(k.ptr(over), k.flag, *k.ptr(over), k.usage)
	}
	for _, k := range intKeys {
		set.IntVar(k.ptr(over), k.flag, *k.ptr(over), k.usage)
	}
	for _, k := range int64Keys {
		set.Int64Var(k.ptr(over), k.flag, *k.ptr(over), k.usage)
	}
	for _, k := range boolKeys {
		set.BoolVar(k.ptr(over), k.flag, *k.ptr(over), k.usage)
	}
	for _, k := range durationKeys {
		set.Var(k.ptr(over), k.flag, k.usage)
	}
	for _, k := range listKeys {
		set.Var(commaList{k.ptr(over)}, k.flag, k.usage)
	}
}

func applyFlags(cfg *Config, flagsSet map[string]bool, over *Config) {
	copyIf(stringKeys, cfg, over, flagsSet)
	copyIf(intKeys, cfg, over, flagsSet)
	copyIf(int64Keys, cfg, over, flagsSet)
	copyIf(boolKeys, cfg, over, flagsSet)
	copyIf(durationKeys, cfg, over, flagsSet)
	for _, k := range listKeys {
		if flagsSet[k.flag] {
			*k.ptr(cfg) = slices.Clone(*k.ptr(over))
		}
	}
}

func copyIf[T any](keys []key[T], cfg, over *Config, flagsSet map[string]bool) {
	for _, k := range keys {
		if flagsSet[k.flag] {
			*k.ptr(cfg) = *k.ptr(over)
		}
	}
}

func applyEnv(cfg *Config, flagsSet map[string]bool, getenv func(string) string, warn io.Writer) {
	for _, k := range stringKeys {
		if text, ok := envValue(k, flagsSet, getenv); ok {
			*k.ptr(cfg) = text
		}
	}
	for _, k := range intKeys {
		if text, ok := envValue(k, flagsSet, getenv); ok {
			if value, err := strconv.Atoi(text); err == nil {
				*k.ptr(cfg) = value
			} else {
				warnEnv(warn, k.env, text, "an integer")
			}
		}
	}
	for _, k := range int64Keys {
		if text, ok := envValue(k, flagsSet, getenv); ok {
			if value, err := strconv.ParseInt(text, 10, 64); err == nil {
				*k.ptr(cfg) = value
			} else {
				warnEnv(warn, k.env, text, "an integer")
			}
		}
	}
	for _, k := range boolKeys {
		if text, ok := envValue(k, flagsSet, getenv); ok {
			if value, err := strconv.ParseBool(text); err == nil {
				*k.ptr(cfg) = value
			} else {
				warnEnv(warn, k.env, text, "a boolean")
			}
		}
	}
	for _, k := range durationKeys {
		if text, ok := envValue(k, flagsSet, getenv); ok {
			var value Duration
			if err := value.Set(text); err == nil {
				*k.ptr(cfg) = value
			} else {
				warnEnv(warn, k.env, text, "a duration")
			}
		}
	}
	for _, k := range listKeys {
		if text, ok := envValue(k, flagsSet, getenv); ok {
			*k.ptr(cfg) = splitList(text)
		}
	}
}

// envValue reads one override; a flag suppresses it.
func envValue[T any](k key[T], flagsSet map[string]bool, getenv func(string) string) (string, bool) {
	if flagsSet[k.flag] {
		return "", false
	}
	text := getenv(envPrefix + k.env)
	return text, text != ""
}

func warnEnv(warn io.Writer, name, value, want string) {
	fmt.Fprintf(warn, "warning: %s%s=%q is not %s, ignoring\n", envPrefix, name, value, want)
}

// Validate reports every fault in one error.
func (c Config) Validate() error {
	var faults []error
	if strings.TrimSpace(c.ListenAddr) == "" {
		faults = append(faults, errors.New("listen_addr is required"))
	}
	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			faults = append(faults, errors.New("public_url must be an http or https origin"))
		}
	}
	for name, link := range map[string]string{"provider_url": c.ProviderURL, "source_url": c.SourceURL} {
		if link == "" {
			continue
		}
		if u, err := url.Parse(link); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			faults = append(faults, fmt.Errorf("%s must be an http or https URL", name))
		}
	}
	if c.RateLimit.Enabled && (c.RateLimit.Max < 1 || c.RateLimit.Window.Duration <= 0) {
		faults = append(faults, errors.New("rate_limit.max and rate_limit.window must be positive when enabled"))
	}
	if c.TargetCooldown.Duration < 0 {
		faults = append(faults, errors.New("target_cooldown must not be negative"))
	}
	if c.MaxConcurrentChecks < 1 {
		faults = append(faults, errors.New("max_concurrent_checks must be at least one"))
	}
	if c.CheckTimeout.Duration <= 0 {
		faults = append(faults, errors.New("check_timeout must be positive"))
	}
	if c.MaxBodySize < 1 {
		faults = append(faults, errors.New("max_body_size must be positive"))
	}
	for _, cidr := range c.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			faults = append(faults, fmt.Errorf("trusted_proxy_cidrs: %q is not a prefix", cidr))
		}
	}
	for _, address := range c.SourceAddresses {
		if _, err := netip.ParseAddr(address); err != nil {
			faults = append(faults, fmt.Errorf("source_addresses: %q is not an address", address))
		}
	}
	return errors.Join(faults...)
}

// Origin is PublicURL without a trailing slash.
func (c Config) Origin() string {
	return strings.TrimSuffix(c.PublicURL, "/")
}
