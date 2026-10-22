package probe

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/pawal/php2shell/engine/verdict"
)

// OracleObservation counts the warnings returned by one session request.
type OracleObservation struct {
	URL         string `json:"url"`
	Status      int    `json:"status,omitempty"`
	InvalidID   int    `json:"invalid_id"`
	FailedRead  int    `json:"failed_read"`
	FailedWrite int    `json:"failed_write"`
}

// oracle uses only the invalid session key in the lab reference request.
func (s *session) oracle(ctx context.Context, target Target, finalURL string) (verdict.Oracle, []OracleObservation, error) {
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
	for _, path := range []string{target.URL(), target.Origin() + "/index.php", finalURL} {
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
		resp, text, err := s.do(ctx, client, req)
		observation := OracleObservation{URL: path}
		if resp != nil {
			observation.Status = resp.StatusCode
		}
		observation.InvalidID = strings.Count(text, "Session ID is too long")
		observation.FailedRead = strings.Count(text, "Failed to read session data")
		observation.FailedWrite = strings.Count(text, "Failed to write session data")
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
		if observation.InvalidID > 0 && observation.FailedRead > 0 {
			if observation.FailedWrite > 0 {
				return verdict.OracleUnpatched, observations, nil
			}
			return verdict.OraclePatched, observations, nil
		}
	}
	return verdict.OracleSilent, observations, nil
}
