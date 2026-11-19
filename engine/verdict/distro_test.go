package verdict

import (
	"strings"
	"testing"
)

func TestVerrevcmp(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1ubuntu2.28", "1ubuntu2.28", 0},
		{"1ubuntu2.28", "1ubuntu2.6", 1},
		{"1ubuntu2.27", "1ubuntu2.28", -1},
		{"4ubuntu2.29", "4ubuntu2.29+esm5", -1},
		{"4ubuntu2.29+esm6", "4ubuntu2.29+esm5", 1},
		{"1~deb12u1", "1", -1},
		{"0ubuntu0.18.04.17+esm14", "0ubuntu0.18.04.17", 1},
		{"01", "1", 0},
	} {
		got := verrevcmp(c.a, c.b)
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("verrevcmp(%q, %q) = %d, want sign of %d", c.a, c.b, got, c.want)
		}
	}
}

// A release a distribution freezes is named with the package carrying the October fixes.
func TestShippedReleases(t *testing.T) {
	for _, c := range []struct {
		header, server, verdict string
		want                    []string
	}{
		{"PHP/8.3.6", "nginx", PossiblyBackported, []string{"shows 8.3.6, likely from Ubuntu, which fixes", "8.3.6 is the release Ubuntu 24.04 ships", "8.3.6-0ubuntu0.24.04.13 (USN-8948-1)"}},
		{"PHP/8.3.6", "Apache/2.4.58 (Ubuntu)", PossiblyBackported, []string{"shows 8.3.6 from ubuntu", "Ubuntu 24.04"}},
		{"PHP/8.5.4", "", PossiblyBackported, []string{"Ubuntu 26.04", "8.5.4-0ubuntu1.5"}},
		{"PHP/8.3.19", "", PossiblyBackported, []string{"likely from Red Hat", "RHEL 10.0", "RHSA-2026:88561"}},
		{"PHP/8.1.2-1ubuntu2.28", "", EOLBranch, []string{"Ubuntu 22.04", "This build, 8.1.2-1ubuntu2.28, includes it."}},
		{"PHP/8.1.2-1ubuntu2.27", "", EOLBranch, []string{"This build, 8.1.2-1ubuntu2.27, is older and lacks those fixes."}},
		{"PHP/7.4.3-4ubuntu2.29", "", EOLBranch, []string{"7.4.3-4ubuntu2.29+esm5 (USN-8948-2)", "is older and lacks"}},
		{"PHP/7.2.24-0ubuntu0.18.04.17+esm14", "", EOLBranch, []string{"Ubuntu 18.04", "includes it."}},
		{"PHP/8.0.30", "", EOLBranch, []string{"RHEL 9", "php-8.0.30-8.el9_8.1"}},
	} {
		got := Judge(Input{Reachable: true, PoweredBy: c.header, Server: c.server})
		if got.Verdict != c.verdict {
			t.Errorf("%s %s: got %s, want %s", c.header, c.server, got.Verdict, c.verdict)
		}
		for _, want := range c.want {
			if !strings.Contains(got.Summary, want) {
				t.Errorf("%s %s lacks %q: %s", c.header, c.server, want, got.Summary)
			}
		}
	}
	for _, c := range []struct{ header, server string }{
		{"PHP/8.3.6", "Apache/2.4.62 (Debian)"},
		{"PHP/8.3.6-1+ubuntu24.04.1+deb.sury.org+1", ""},
		{"PHP/8.3.7", ""},
		{"PHP/8.5.4RC1", ""},
	} {
		if got := Judge(Input{Reachable: true, PoweredBy: c.header, Server: c.server}); strings.Contains(got.Summary, " ships;") {
			t.Errorf("%s %s named a distribution: %s", c.header, c.server, got.Summary)
		}
	}
}

// A revision that settles the October fixes replaces the sentence that the version cannot show them.
func TestRevisionReplacesUncertainty(t *testing.T) {
	got := Judge(Input{Reachable: true, PoweredBy: "PHP/8.1.2-1ubuntu2.28"}).Summary
	if strings.Contains(got, "cannot show whether the fix is applied") || !strings.Contains(got, "includes it.") {
		t.Errorf("%s", got)
	}
	if bare := Judge(Input{Reachable: true, PoweredBy: "PHP/8.1.2"}).Summary; !strings.Contains(bare, "cannot show whether the fix is applied") {
		t.Errorf("bare: %s", bare)
	}
}
