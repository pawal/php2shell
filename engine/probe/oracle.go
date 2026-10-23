package probe

import (
	"bytes"
	"context"
	"html"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/pawal/php2shell/engine/verdict"
)

// OracleObservation counts the warnings returned by one session request.
type OracleObservation struct {
	Blocked     string         `json:"inspection_blocked,omitempty"`
	URL         string         `json:"url"`
	Status      int            `json:"status,omitempty"`
	InvalidID   int            `json:"invalid_id"`
	FailedRead  int            `json:"failed_read"`
	FailedWrite int            `json:"failed_write"`
	Complete    bool           `json:"response_complete"`
	Error       string         `json:"error,omitempty"`
	Result      verdict.Oracle `json:"session_result"`
	// Lines are the distinct warning lines counted, as plain text.
	Lines []string `json:"lines,omitempty"`
}

// The warnings the session request counts.
const (
	invalidIDWarning   = "Session ID is too long"
	failedReadWarning  = "Failed to read session data"
	failedWriteWarning = "Failed to write session data"
)

// Bounds on the warning lines kept as evidence.
const (
	maxWarningLines = 6
	maxWarningLine  = 300
)

var (
	lineBreak = regexp.MustCompile(`(?i)<br\s*/?>|\n`)
	markup    = regexp.MustCompile(`<[^>]*>`)
)

// warningLines keeps each distinct line that carries a counted warning.
func warningLines(text string) []string {
	var lines []string
	for _, line := range lineBreak.Split(text, -1) {
		if !strings.Contains(line, invalidIDWarning) && !strings.Contains(line, failedReadWarning) && !strings.Contains(line, failedWriteWarning) {
			continue
		}
		line = strings.Join(strings.Fields(html.UnescapeString(markup.ReplaceAllString(line, ""))), " ")
		if len(line) > maxWarningLine {
			line = strings.ToValidUTF8(line[:maxWarningLine], "")
		}
		lines = append(lines, line)
	}
	lines = dedupe(lines)
	if len(lines) > maxWarningLines {
		lines = lines[:maxWarningLines]
	}
	return lines
}

// oracle uses only the invalid session key in the lab reference request.
func (s *session) oracle(ctx context.Context, target Target, passive Passive) (verdict.Oracle, []OracleObservation, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("PHP_SESSION_UPLOAD_PROGRESS", "probe"); err != nil {
		return verdict.OracleNotRun, nil, err
	}
	file, err := writer.CreateFormFile("f", "probe.txt")
	if err != nil {
		return verdict.OracleNotRun, nil, err
	}
	if _, err := file.Write([]byte("1")); err != nil {
		return verdict.OracleNotRun, nil, err
	}
	if err := writer.Close(); err != nil {
		return verdict.OracleNotRun, nil, err
	}
	client := &http.Client{Transport: s.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	seen := map[string]bool{}
	var observations []OracleObservation
	result := verdict.OracleSilent
	for _, path := range oraclePaths(target, passive) {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body.Bytes()))
		if err != nil {
			return verdict.OracleSilent, observations, err
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("Cookie", "PHPSESSID=_")
		resp, text, complete, err := s.do(ctx, client, req)
		observation := OracleObservation{URL: path, Complete: complete, Result: verdict.OracleSilent}
		if resp != nil {
			observation.Status = resp.StatusCode
			observation.Blocked = inspectionBlock(resp, text)
		}
		observation.InvalidID = strings.Count(text, invalidIDWarning)
		observation.FailedRead = strings.Count(text, failedReadWarning)
		observation.FailedWrite = strings.Count(text, failedWriteWarning)
		observation.Lines = warningLines(text)
		if err != nil {
			observation.Error = err.Error()
		}
		if err == nil && complete && observation.Blocked == "" && observation.Status >= 200 && observation.Status < 300 && observation.InvalidID > 0 && observation.FailedRead > 0 {
			observation.Result = verdict.OraclePatched
			if observation.FailedWrite > 0 {
				observation.Result = verdict.OracleUnpatched
			}
		}
		observations = append(observations, observation)
		if err != nil {
			if ctx.Err() != nil {
				return verdict.OracleSilent, observations, ctx.Err()
			}
			// Address policy errors remain errors even after a successful GET.
			if _, ok := err.(*PolicyError); ok {
				return verdict.OracleSilent, observations, err
			}
			continue
		}
		if observation.Blocked != "" {
			return result, observations, nil
		}
		if observation.Result == verdict.OracleUnpatched || result == verdict.OracleSilent {
			result = observation.Result
		}
	}
	return result, observations, nil
}

// oraclePaths adds a WordPress login fallback only when the page identifies it.
func oraclePaths(target Target, passive Passive) []string {
	paths := []string{target.URL(), target.Origin() + "/index.php", passive.FinalURL}
	for _, hint := range passive.Hints {
		if strings.Contains(strings.ToLower(hint), "wordpress") {
			base, err := url.Parse(passive.FinalURL)
			if err == nil && base.Host != "" {
				paths = append(paths, base.ResolveReference(&url.URL{Path: "/wp-login.php"}).String())
			}
			break
		}
	}
	paths = append(paths, passive.Paths...)
	return dedupe(paths)
}
