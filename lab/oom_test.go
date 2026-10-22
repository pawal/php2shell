package lab

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOOMControl checks an ordinary allocation failure, not a CVE trigger.
func TestOOMControl(t *testing.T) {
	if os.Getenv("PHP2SHELL_OOM_CONTROL") == "" {
		t.Skip("make test-oom-control runs this isolated Docker experiment")
	}
	root, err := filepath.Abs("oom-control")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"8.5.11", "8.5.12"} {
		for _, display := range []string{"1", "0"} {
			t.Run(version+"/display_errors="+display, func(t *testing.T) {
				id := docker(t, "run", "--detach", "--rm", "--network", "none", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1", "--pids-limit", "64",
					"--label", "php2shell.lab=oom-control", "--env", "LAB_DISPLAY_ERRORS="+display,
					"--mount", "type=bind,src="+root+",dst=/var/www/html,readonly", "php:"+version+"-apache")
				t.Cleanup(func() { docker(t, "rm", "--force", id) })
				ready := false
				for range 25 {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					err := exec.CommandContext(ctx, "docker", "exec", id, "php", "-r", `exit(@file_get_contents('http://127.0.0.1/') === "ok\n" ? 0 : 1);`).Run()
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
				request := `$ctx = stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 5]]);
$body = file_get_contents('http://127.0.0.1/oom.php', false, $ctx);
$headers = http_get_last_response_headers();
$pid = 0;
foreach ($headers as $header) {
    if (preg_match('/^X-Lab-PHP-Pid: ([0-9]+)/i', $header, $matches)) { $pid = (int) $matches[1]; }
}
echo json_encode(['version' => PHP_VERSION, 'status' => http_get_last_response_headers()[0],
    'worker_pid' => $pid,
    'memory_fatal' => str_contains($body, 'Allowed memory size of'),
    'unexpected_success' => str_contains($body, 'unexpected success')]);`
				var result struct {
					Version           string `json:"version"`
					Status            string `json:"status"`
					MemoryFatal       bool   `json:"memory_fatal"`
					WorkerPID         int    `json:"worker_pid"`
					UnexpectedSuccess bool   `json:"unexpected_success"`
				}
				data := docker(t, "exec", id, "php", "-r", request)
				if err := json.Unmarshal([]byte(data), &result); err != nil {
					t.Fatalf("decode result: %v: %s", err, data)
				}
				if result.Version != version || result.MemoryFatal != (display == "1") || result.UnexpectedSuccess {
					t.Fatalf("unexpected allocation-failure result: %+v", result)
				}
				if result.WorkerPID <= 0 {
					t.Fatal("response omitted worker PID")
				}
				docker(t, "exec", id, "test", "-d", "/proc/"+strconv.Itoa(result.WorkerPID))
				logs := docker(t, "logs", id)
				if !strings.Contains(logs, "Allowed memory size of") {
					t.Fatal("allocation failure missing from Apache logs")
				}
				health := docker(t, "exec", id, "php", "-r", `echo file_get_contents('http://127.0.0.1/');`)
				if health != "ok" {
					t.Fatalf("subsequent request failed: %s", health)
				}
				if got := docker(t, "inspect", "--format", "{{.State.OOMKilled}}", id); got != "false" {
					t.Fatalf("container hit its memory cap: %s", got)
				}
				t.Logf("PHP=%s display_errors=%s status=%s memory_fatal_in_body=%t fatal_in_log=true worker_survived=true subsequent_request=ok container_oom_killed=false", version, display, result.Status, result.MemoryFatal)
			})
		}
	}
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args[:1], " "), err, output)
	}
	return strings.TrimSpace(string(output))
}
