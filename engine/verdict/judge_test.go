package verdict

import (
	"slices"
	"strings"
	"testing"
)

func TestJudge(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want string
	}{
		{"unreachable", Input{}, Unreachable},
		{"oracle unpatched", Input{Reachable: true, PoweredBy: "PHP/8.5.11", Oracle: OracleUnpatched}, LikelyVulnerable},
		{"oracle unpatched past a fixed header", Input{Reachable: true, PoweredBy: "PHP/8.5.12", Oracle: OracleUnpatched}, LikelyVulnerable},
		{"oracle patched", Input{Reachable: true, PoweredBy: "PHP/8.5.12", Oracle: OraclePatched}, LikelyPatched},
		{"oracle patched on a possible backport", Input{Reachable: true, PoweredBy: "PHP/8.3.6-0ubuntu0.24.04.13", Oracle: OraclePatched}, PossiblyBackported},
		{"oracle patched without version", Input{Reachable: true, Oracle: OraclePatched}, Inconclusive},
		{"session change without complete backport evidence", Input{Reachable: true, PoweredBy: "PHP/8.5.11", Oracle: OraclePatched}, LikelyVulnerable},
		{"fixed header", Input{Reachable: true, PoweredBy: "PHP/8.4.27", Oracle: OracleNotRun}, LikelyPatched},
		{"affected header", Input{Reachable: true, PoweredBy: "PHP/8.4.26", Oracle: OracleSilent}, LikelyVulnerable},
		{"ubuntu header", Input{Reachable: true, PoweredBy: "PHP/8.3.6-0ubuntu0.24.04.13", Oracle: OracleSilent}, PossiblyBackported},
		{"rocky server header", Input{Reachable: true, Server: "Apache (Rocky Linux) PHP/8.2.13"}, PossiblyBackported},
		{"eol header", Input{Reachable: true, PoweredBy: "PHP/7.4.33"}, EOLBranch},
		{"future branch", Input{Reachable: true, PoweredBy: "PHP/9.0.0"}, Inconclusive},
		{"hints only", Input{Reachable: true, Hints: []string{"PHPSESSID cookie"}, Oracle: OracleSilent}, Inconclusive},
		{"inspection blocked", Input{Reachable: true, InspectionBlocked: "JavaScript bot challenge", Oracle: OracleNotRun}, InspectionBlocked},
		{"version on a blocked path", Input{Reachable: true, PoweredBy: "PHP/8.5.12", InspectionBlocked: "HTTP 403 access denied"}, InspectionBlocked},
		{"nothing", Input{Reachable: true, Oracle: OracleSilent}, NoPHPSignal},
	}
	for _, c := range cases {
		got := Judge(c.in)
		if got.Verdict != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got.Verdict, c.want)
		}
		if got.Summary == "" || len(got.Recommendations) == 0 {
			t.Errorf("%s: a verdict without a summary or recommendations", c.name)
		}
	}
}

// Every verdict code carries advice.
func TestRecommendationsCoverEveryVerdict(t *testing.T) {
	for _, code := range []string{Vulnerable, Patched, LikelyVulnerable, PossiblyBackported, EOLBranch, LikelyPatched, Inconclusive, NoPHPSignal, Unreachable, InspectionBlocked} {
		if len(recommendations[code]) == 0 {
			t.Errorf("%s has no recommendations", code)
		}
	}
}

// Older session behaviour under a fixed header is conflicting evidence.
func TestUnpatchedUnderFixedHeader(t *testing.T) {
	got := Judge(Input{Reachable: true, PoweredBy: "PHP/8.5.12", Oracle: OracleUnpatched})
	if !strings.Contains(got.Summary, "verify the running workers, the session extension") {
		t.Errorf("summary: %s", got.Summary)
	}
}

// A phpinfo() version stands in for a missing header and adds removal advice.
func TestPHPInfoVersion(t *testing.T) {
	got := Judge(Input{Reachable: true, Server: "nginx", PHPInfo: "8.4.27", Oracle: OracleNotRun})
	if got.Verdict != LikelyPatched || !strings.Contains(got.Summary, "phpinfo() page shows 8.4.27") || !slices.Contains(got.Recommendations, RemovePHPInfo) {
		t.Errorf("phpinfo: %+v", got)
	}
	header := Judge(Input{Reachable: true, PoweredBy: "PHP/8.4.26", PHPInfo: "8.4.27"})
	if header.Verdict != LikelyVulnerable || !strings.Contains(header.Summary, "header shows") {
		t.Errorf("header first: %+v", header)
	}
	if slices.Contains(recommendations[LikelyPatched], RemovePHPInfo) {
		t.Error("advice leaked into the shared recommendations")
	}
}

// phpinfo() settings explain a silent session request, credit the interim
// measure and name what to restart.
func TestPHPInfoSettings(t *testing.T) {
	hidden := Judge(Input{Reachable: true, PHPInfo: "8.4.26", Oracle: OracleSilent,
		PHPInfoSettings: map[string]string{ServerAPI: "FPM/FastCGI", DisplayErrors: "Off", UploadProgress: "On", SaveHandler: "files"}})
	if hidden.Verdict != LikelyVulnerable || !strings.Contains(hidden.Summary, "phpinfo() page shows display_errors Off.") || strings.Contains(hidden.Summary, "interim") {
		t.Errorf("hidden errors: %s", hidden.Summary)
	}
	if slices.Contains(hidden.Recommendations, Restart) || !slices.ContainsFunc(hidden.Recommendations, func(s string) bool { return strings.HasPrefix(s, "Restart every PHP-FPM pool") }) {
		t.Errorf("restart advice: %v", hidden.Recommendations)
	}
	measured := Judge(Input{Reachable: true, PHPInfo: "8.3.30", Oracle: OracleNotRun,
		PHPInfoSettings: map[string]string{UploadProgress: "Off", ServerAPI: "Apache 2.0 Handler"}})
	if !strings.Contains(measured.Summary, "session.upload_progress.enabled Off, an interim measure for the session paths of CVE-2026-109619") || !strings.Contains(measured.Summary, "does not mitigate CVE-2026-109618") {
		t.Errorf("measure: %s", measured.Summary)
	}
	if !slices.ContainsFunc(measured.Recommendations, func(s string) bool { return strings.HasPrefix(s, "Restart Apache") }) {
		t.Errorf("apache restart: %v", measured.Recommendations)
	}
	fixed := Judge(Input{Reachable: true, PHPInfo: "8.4.27", PHPInfoSettings: map[string]string{UploadProgress: "Off"}})
	if strings.Contains(fixed.Summary, "interim") {
		t.Errorf("a fixed version needs no measure: %s", fixed.Summary)
	}
	plain := Judge(Input{Reachable: true, PoweredBy: "PHP/8.4.26", Oracle: OracleSilent})
	if !strings.Contains(plain.Summary, "errors are hidden, upload progress is off") || !slices.Contains(plain.Recommendations, Restart) {
		t.Errorf("without phpinfo(): %+v", plain)
	}
}

// Disagreeing sources are named, and the version least likely fixed decides.
func TestDisagreeingVersions(t *testing.T) {
	old := mustVersion(t, "PHP/8.5.11")
	got := Judge(Input{Reachable: true, PoweredBy: "PHP/8.5.12", Sightings: []Sighting{{"header on /old.php", old}}})
	if got.Verdict != LikelyVulnerable || got.Version.String() != "8.5.11" {
		t.Fatalf("worst version: %+v", got)
	}
	if !strings.HasPrefix(got.Summary, "The header on /old.php shows 8.5.11; the fix is in 8.5.12.") || !strings.Contains(got.Summary, "Sources disagree: the header shows 8.5.12.") {
		t.Errorf("summary: %s", got.Summary)
	}
	same := Judge(Input{Reachable: true, PoweredBy: "PHP/8.5.11", Sightings: []Sighting{{"header on /old.php", old}}})
	if strings.Contains(same.Summary, "disagree") || !strings.HasPrefix(same.Summary, "The header shows") {
		t.Errorf("agreeing sources: %s", same.Summary)
	}
	tie := Judge(Input{Reachable: true, PoweredBy: "PHP/8.5.11", PHPInfo: "8.5.10"})
	if !strings.HasPrefix(tie.Summary, "The header shows 8.5.11") || !strings.Contains(tie.Summary, "the phpinfo() page shows 8.5.10") {
		t.Errorf("tie: %s", tie.Summary)
	}
}

func mustVersion(t *testing.T, header string) Version {
	t.Helper()
	v, ok := ParseVersion(header, "")
	if !ok {
		t.Fatalf("no version in %q", header)
	}
	return v
}

// A layer in front is named only where it weakens the reading.
func TestFrontNote(t *testing.T) {
	front := []string{"Cloudflare"}
	for _, c := range []struct {
		name string
		in   Input
		note bool
	}{
		{"no php signal", Input{Reachable: true, Front: front}, true},
		{"inconclusive", Input{Reachable: true, Hints: []string{"PHPSESSID cookie"}, Front: front}, true},
		{"silent session request", Input{Reachable: true, PoweredBy: "PHP/8.4.27", Oracle: OracleSilent, Front: front}, true},
		{"blocked", Input{Reachable: true, InspectionBlocked: "HTTP 403 access denied", Front: front}, true},
		{"named block", Input{Reachable: true, InspectionBlocked: "Sansec Shield firewall", Front: []string{"Sucuri"}}, false},
		{"header version", Input{Reachable: true, PoweredBy: "PHP/8.4.27", Oracle: OracleNotRun, Front: front}, false},
		{"session answer", Input{Reachable: true, Oracle: OracleUnpatched, Front: front}, false},
		{"nothing in front", Input{Reachable: true}, false},
	} {
		got := Judge(c.in).Summary
		if strings.Contains(got, "in front of the site") != c.note {
			t.Errorf("%s: %s", c.name, got)
		}
	}
	if got := frontNote([]string{"a proxy"}); !strings.HasPrefix(got, " A proxy answers in front") {
		t.Errorf("generic: %q", got)
	}
	if got := frontNote([]string{"Cloudflare", "Varnish"}); !strings.HasPrefix(got, " Cloudflare and Varnish answer in front") {
		t.Errorf("plural: %q", got)
	}
}

// An unreachable site names the reason, and a likely block only for network failures.
func TestFailureNote(t *testing.T) {
	timedOut := Judge(Input{Failure: FailedTimeout}).Summary
	if timedOut != "The site did not answer, so nothing was checked. The connection timed out. If the site opens in a browser, its host may be blocking the checker's address." {
		t.Errorf("timeout: %s", timedOut)
	}
	if certificate := Judge(Input{Failure: FailedCertificate}).Summary; strings.Contains(certificate, "blocking") || !strings.Contains(certificate, "The site's TLS certificate was not accepted.") {
		t.Errorf("certificate: %s", certificate)
	}
	if plain := Judge(Input{}).Summary; plain != "The site did not answer, so nothing was checked." {
		t.Errorf("no reason: %s", plain)
	}
}

// Another platform is named only when nothing shows PHP.
func TestOtherPlatformsNote(t *testing.T) {
	java := []string{"Java (JSESSIONID cookie)"}
	alone := Judge(Input{Reachable: true, Platforms: java, Oracle: OracleSilent}).Summary
	if !strings.HasPrefix(alone, "Nothing in the answers shows PHP; they point to Java (JSESSIONID cookie) instead. Other paths on the host may still run PHP.") || !strings.Contains(alone, "session request showed nothing") {
		t.Errorf("alone: %s", alone)
	}
	mixed := Judge(Input{Reachable: true, Platforms: java, Hints: []string{"PHPSESSID cookie"}})
	if mixed.Verdict != Inconclusive || strings.Contains(mixed.Summary, "point to") {
		t.Errorf("mixed: %+v", mixed)
	}
}

func TestSessionSignalCannotEstablishBothCVEFixes(t *testing.T) {
	for _, header := range []string{"", "PHP/8.5.11", "PHP/8.5.12", "PHP/8.3.6-0ubuntu0.24.04.13"} {
		got := Judge(Input{Reachable: true, PoweredBy: header, Oracle: OraclePatched, OraclePaths: []string{"https://example.com/app.php"}})
		if got.Verdict == Patched || got.Verdict == Vulnerable || got.Confidence == "high" || !strings.Contains(got.Summary, "https://example.com/app.php") || !strings.Contains(got.Summary, "does not establish a complete fix") || !strings.Contains(got.Summary, "CVE-2026-109618 is assessed from version evidence") {
			t.Fatalf("%s: %+v", header, got)
		}
		if slices.ContainsFunc(got.Recommendations, func(advice string) bool { return strings.Contains(advice, "No action is needed") }) {
			t.Fatalf("unverified fixes dismissed: %+v", got)
		}
	}
}
