package lab

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSessionVariants compares benign reachability probes, not CVE triggers.
func TestSessionVariants(t *testing.T) {
	if os.Getenv("PHP2SHELL_SESSION_VARIANTS") == "" {
		t.Skip("make test-session-variants runs this isolated Docker experiment")
	}
	root, err := filepath.Abs("session-variants")
	if err != nil {
		t.Fatal(err)
	}
	configs := []struct{ name, display, progress, cookies string }{
		{"visible/cookies-only", "1", "1", "1"},
		{"visible/all-sources", "1", "1", "0"},
		{"hidden/cookies-only", "0", "1", "1"},
		{"hidden/all-sources", "0", "1", "0"},
		{"progress-off/all-sources", "1", "0", "0"},
	}
	for _, version := range []string{"8.5.11", "8.5.12"} {
		for _, config := range configs {
			t.Run(version+"/"+config.name, func(t *testing.T) {
				id := docker(t, "run", "--detach", "--rm", "--network", "none", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1", "--pids-limit", "64",
					"--label", "php2shell.lab=session-variants", "--env", "LAB_DISPLAY="+config.display,
					"--env", "LAB_PROGRESS="+config.progress, "--env", "LAB_COOKIES="+config.cookies,
					"--mount", "type=bind,src="+root+",dst=/var/www/html,readonly", "php:"+version+"-apache", "sh", "-c",
					`printf 'display_errors=%s\ndisplay_startup_errors=%s\nlog_errors=1\nerror_reporting=E_ALL\nexpose_php=0\nsession.upload_progress.enabled=%s\nsession.use_only_cookies=%s\n' "$LAB_DISPLAY" "$LAB_DISPLAY" "$LAB_PROGRESS" "$LAB_COOKIES" > /usr/local/etc/php/conf.d/zz-lab.ini; exec apache2-foreground`)
				t.Cleanup(func() { docker(t, "rm", "--force", id) })
				ready := false
				for range 25 {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					err := exec.CommandContext(ctx, "docker", "exec", id, "php", "-n", "-r", `exit(str_starts_with((string) @file_get_contents('http://127.0.0.1/'), 'ok pid=') ? 0 : 1);`).Run()
					cancel()
					if err == nil {
						ready = true
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				if !ready {
					t.Fatal("isolated Apache did not become ready")
				}
				var report struct {
					Version string `json:"version"`
					Results []struct {
						Name           string `json:"name"`
						Status         string `json:"status"`
						InvalidID      int    `json:"invalid_id"`
						FailedRead     int    `json:"failed_read"`
						FailedWrite    int    `json:"failed_write"`
						PHPDiagnostic  bool   `json:"php_diagnostic"`
						AdvertisesPHP  bool   `json:"advertises_php"`
						SetsSession    bool   `json:"sets_session"`
						RequestBytes   int    `json:"request_bytes"`
						BodyBytes      int    `json:"body_bytes"`
						ScriptReached  bool   `json:"script_reached"`
						ServerConfig   string `json:"server_config"`
						WorkerSurvived bool   `json:"worker_survived"`
					} `json:"results"`
				}
				// The client does not load server INI settings or their startup diagnostics.
				data := docker(t, "exec", id, "php", "-n", "/var/www/html/client.php")
				if err := json.Unmarshal([]byte(data), &report); err != nil {
					t.Fatalf("decode result: %v: %s", err, data)
				}
				if report.Version != version || len(report.Results) != 9 {
					t.Fatalf("unexpected experiment: %+v", report)
				}
				for _, result := range report.Results {
					if !result.ScriptReached || !result.WorkerSurvived || result.AdvertisesPHP || result.RequestBytes > 1024 || result.Status != "HTTP/1.1 200 OK" || result.ServerConfig != config.display+config.progress+config.cookies {
						t.Errorf("unexpected request outcome: %+v", result)
					}
					accepted := !strings.HasPrefix(result.Name, "query-") || config.cookies == "0"
					warned := config.display == "1" && config.progress == "1" && accepted && strings.HasSuffix(result.Name, "-invalid")
					if (result.InvalidID > 0) != warned || (result.FailedRead > 0) != warned || result.PHPDiagnostic != warned || (result.FailedWrite > 0) != (warned && version == "8.5.11") {
						t.Errorf("session warning behaviour changed: %+v", result)
					}
					cookie := config.progress == "1" && accepted && strings.HasSuffix(result.Name, "-nul")
					if result.SetsSession != cookie {
						t.Errorf("session-cookie reachability behaviour changed: %+v", result)
					}
					t.Logf("PHP=%s config=%s case=%s warnings=%d/%d/%d php_diagnostic=%t session_cookie=%t body_bytes=%d worker_survived=%t", version, config.name, result.Name,
						result.InvalidID, result.FailedRead, result.FailedWrite, result.PHPDiagnostic, result.SetsSession, result.BodyBytes, result.WorkerSurvived)
				}
				if got := docker(t, "inspect", "--format", "{{.State.OOMKilled}}", id); got != "false" {
					t.Fatalf("container hit its memory cap: %s", got)
				}
			})
		}
	}
}
