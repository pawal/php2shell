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
		{"oracle unpatched", Input{Reachable: true, PoweredBy: "PHP/8.5.11", Oracle: OracleUnpatched}, Vulnerable},
		{"oracle unpatched past a fixed header", Input{Reachable: true, PoweredBy: "PHP/8.5.12", Oracle: OracleUnpatched}, Vulnerable},
		{"oracle patched", Input{Reachable: true, PoweredBy: "PHP/8.5.12", Oracle: OraclePatched}, Patched},
		{"oracle patched on a backport", Input{Reachable: true, PoweredBy: "PHP/8.3.6-0ubuntu0.24.04.13", Oracle: OraclePatched}, Patched},
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

// An unpatched answer under a fixed header names the stale session extension.
func TestUnpatchedUnderFixedHeader(t *testing.T) {
	got := Judge(Input{Reachable: true, PoweredBy: "PHP/8.5.12", Oracle: OracleUnpatched})
	if !strings.Contains(got.Summary, "session extension is older") {
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
