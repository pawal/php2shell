// Command php2shell checks a website for PHP2Shell, CVE-2026-109618 and
// CVE-2026-109619, from the command line or as a service.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/pawal/php2shell/engine/probe"
	"github.com/pawal/php2shell/engine/verdict"
	"github.com/pawal/php2shell/server"
)

// Exit codes.
const (
	exitOK      = 0
	exitUsage   = 1
	exitFailure = 2
)

const synopsis = `Check a website for PHP2Shell, CVE-2026-109618 and CVE-2026-109619.

Usage:
  php2shell check [flags] <url>   check one site and print the verdict
  php2shell serve [flags]         run the web service
  php2shell version               print the build

"php2shell <subcommand> -h" prints the flags of one subcommand.
`

const checkFlags = `Check flags:
  -json              print the report as JSON
  -passive           read the advertised version only; send no session request
  -allow-non-global  check non-global addresses and any port, for a lab
  -timeout <dur>     wall clock the whole check may take (default 15s)
  -fingerprints <file>  add a separately downloaded PHP fingerprint database
`

const serveFlags = `Serve flags:
  -config <file>   read the configuration from this file
  -dump-config     print the effective configuration and exit

Every configuration key also has a flag and a PHP2SHELL_* environment
variable, listed below: a flag beats the variable, which beats the file.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, synopsis)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, synopsis+"\n"+checkFlags+"\n"+serveFlags+"\nConfiguration flags:\n"+server.FlagUsage())
		return exitOK
	case "check":
		return check(ctx, args[1:], stdout, stderr)
	case "serve":
		return serve(ctx, args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, buildVersion())
		return exitOK
	}
	fmt.Fprintf(stderr, "%s\nphp2shell: unknown subcommand %q\n", synopsis, args[0])
	return exitUsage
}

func check(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("check", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	asJSON := set.Bool("json", false, "")
	passive := set.Bool("passive", false, "")
	allowNonGlobal := set.Bool("allow-non-global", false, "")
	timeout := set.Duration("timeout", 15*time.Second, "")
	fingerprints := set.String("fingerprints", "", "")
	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, checkFlags)
			return exitOK
		}
		fmt.Fprintf(stderr, "php2shell check: %v\n\n%s", err, checkFlags)
		return exitUsage
	}
	if set.NArg() != 1 {
		fmt.Fprintf(stderr, "php2shell check: expected one URL\n\n%s", checkFlags)
		return exitUsage
	}
	target, err := probe.ParseTarget(set.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "php2shell check: %v\n", err)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	prober := &probe.Prober{AllowNonGlobal: *allowNonGlobal, UserAgent: userAgent("")}
	if *fingerprints != "" {
		prober.Fingerprints, err = probe.LoadFingerprintDatabase(*fingerprints)
		if err != nil {
			fmt.Fprintf(stderr, "php2shell check: %v\n", err)
			return exitUsage
		}
	}
	input, evidence, err := prober.Check(ctx, target, !*passive)
	if err != nil {
		fmt.Fprintf(stderr, "php2shell check: %v\n", err)
		return exitFailure
	}
	result := verdict.Judge(input)
	if *asJSON {
		report := server.Report{
			Target: target.URL(), Result: result, OracleRun: input.Oracle != verdict.OracleNotRun,
			Evidence: evidence, LocalCheck: server.LocalCheck, CheckedAt: time.Now().UTC(),
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return exitFailure
		}
		return exitOK
	}
	fmt.Fprintf(stdout, "%s: %s (%s confidence)\n%s\n", target.URL(), result.Verdict, result.Confidence, result.Summary)
	for _, line := range result.Recommendations {
		fmt.Fprintf(stdout, "  - %s\n", line)
	}
	return exitOK
}

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, serveFlags+"\nConfiguration flags:\n"+server.FlagUsage())
		return exitOK
	}
	cfg, startup, err := server.LoadConfig(args, os.Getenv, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "php2shell serve: %v\n", err)
		return exitUsage
	}
	if startup.DumpConfig {
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(stderr, "php2shell serve: %v\n", err)
			return exitUsage
		}
		if err := cfg.Dump(stdout); err != nil {
			return exitFailure
		}
		return exitOK
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	prober := &probe.Prober{AllowNonGlobal: cfg.AllowNonGlobalAddresses, UserAgent: userAgent(cfg.Origin())}
	if cfg.FingerprintFile != "" {
		prober.Fingerprints, err = probe.LoadFingerprintDatabase(cfg.FingerprintFile)
		if err != nil {
			fmt.Fprintf(stderr, "php2shell serve: %v\n", err)
			return exitUsage
		}
	}
	srv, err := server.New(cfg, buildVersion(), prober, logger)
	if err != nil {
		fmt.Fprintf(stderr, "php2shell serve: %v\n", err)
		return exitUsage
	}
	if err := srv.Run(ctx); err != nil {
		logger.Error("serve", "error", err)
		return exitFailure
	}
	return exitOK
}

// userAgent names the tool and, for a public instance, its about page.
func userAgent(origin string) string {
	ua := probe.DefaultUserAgent + "/" + strings.TrimPrefix(buildVersion(), "v")
	if origin != "" {
		ua += " (+" + origin + "/about)"
	}
	return ua
}

// buildVersion is the module version and commit Go stamped into the binary.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	version := strings.TrimSuffix(info.Main.Version, "+dirty")
	if version == "" || version == "(devel)" {
		version = "devel"
	}
	if len(revision) >= 12 && !strings.Contains(version, revision[:12]) {
		version += "+" + revision[:7]
	}
	if modified {
		version += ".dirty"
	}
	return version
}
