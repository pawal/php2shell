// Package verdict judges what a check observed against the fixed releases.
package verdict

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// fixed is the first release of each branch carrying the fix.
var fixed = map[[2]int]int{
	{8, 2}: 35,
	{8, 3}: 36,
	{8, 4}: 27,
	{8, 5}: 12,
}

// Version is a PHP version as a response header advertises it.
type Version struct {
	Raw    string `json:"raw"`
	Major  int    `json:"major"`
	Minor  int    `json:"minor"`
	Patch  int    `json:"patch"`
	Suffix string `json:"suffix,omitempty"`
	// Distro is the packager the header or the version names, if any.
	Distro string `json:"distro,omitempty"`
}

var phpVersion = regexp.MustCompile(`(?i)\bPHP/(\d+)\.(\d+)\.(\d+)([-+~][^\s,;()]{0,63})?`)

// Distribution names as they appear in a Server header.
var serverDistros = []struct{ token, distro string }{
	{"(ubuntu)", "ubuntu"},
	{"(debian)", "debian"},
	{"(red hat", "redhat"},
	{"(rocky", "redhat"},
	{"(almalinux", "redhat"},
	{"(centos", "redhat"},
	{"(fedora)", "fedora"},
}

// ParseVersion reads the PHP version from X-Powered-By, then Server.
func ParseVersion(poweredBy, server string) (Version, bool) {
	for _, header := range []string{poweredBy, server} {
		m := phpVersion.FindStringSubmatch(header)
		if m == nil {
			continue
		}
		v := Version{Raw: m[0], Suffix: m[4]}
		v.Major, _ = strconv.Atoi(m[1])
		v.Minor, _ = strconv.Atoi(m[2])
		v.Patch, _ = strconv.Atoi(m[3])
		v.Distro = distro(v.Suffix, server)
		return v, true
	}
	return Version{}, false
}

// distro names the packager from the version suffix, else the Server header.
func distro(suffix, server string) string {
	s := strings.ToLower(suffix)
	switch {
	case strings.Contains(s, "sury"):
		return "sury"
	case strings.Contains(s, "ubuntu"):
		return "ubuntu"
	case strings.Contains(s, "deb"):
		return "debian"
	case strings.Contains(s, ".el"):
		return "redhat"
	}
	lower := strings.ToLower(server)
	for _, d := range serverDistros {
		if strings.Contains(lower, d.token) {
			return d.distro
		}
	}
	return ""
}

// Branch is where a version stands against the fix.
type Branch string

const (
	BranchFixed    Branch = "fixed"
	BranchAffected Branch = "affected"
	BranchEOL      Branch = "eol"
	BranchUnknown  Branch = "unknown"
)

// Standing places a version against the fixed-release table.
func (v Version) Standing() Branch {
	if fix, ok := fixed[[2]int{v.Major, v.Minor}]; ok {
		if v.Patch >= fix {
			return BranchFixed
		}
		return BranchAffected
	}
	if v.Major < 8 || (v.Major == 8 && v.Minor < 2) {
		return BranchEOL
	}
	return BranchUnknown
}

// FixedIn names the release that fixes this version's branch, if any.
func (v Version) FixedIn() string {
	if fix, ok := fixed[[2]int{v.Major, v.Minor}]; ok {
		return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(fix)
	}
	return ""
}

// String is major.minor.patch.
func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// Backports reports a packager known to fix a release without changing the
// upstream version it advertises.
func (v Version) Backports() bool {
	switch v.Distro {
	case "ubuntu", "redhat":
		return true
	case "debian":
		return v.Standing() == BranchEOL
	}
	return false
}

// Sighting is a PHP version one source showed, named with where it was seen.
type Sighting struct {
	Source  string
	Version Version
}

// sightings lists every version a check saw, the header and phpinfo() page first.
func sightings(in Input) []Sighting {
	var all []Sighting
	if v, ok := ParseVersion(in.PoweredBy, in.Server); ok {
		all = append(all, Sighting{"header", v})
	}
	if in.PHPInfo != "" {
		if v, ok := ParseVersion("PHP/"+in.PHPInfo, in.Server); ok {
			all = append(all, Sighting{"phpinfo() page", v})
		}
	}
	return append(all, in.Sightings...)
}

// worst picks the sighting least likely to carry the fix; earlier ones win ties.
func worst(all []Sighting) Sighting {
	chosen := all[0]
	for _, s := range all[1:] {
		if s.Version.rank() < chosen.Version.rank() {
			chosen = s
		}
	}
	return chosen
}

func (v Version) rank() int {
	switch v.Standing() {
	case BranchEOL:
		return 0
	case BranchAffected:
		return 1
	case BranchUnknown:
		return 2
	}
	return 3
}

// disagreement names the sources that show a release other than v.
func disagreement(v Version, all []Sighting) string {
	var others []string
	seen := map[string]bool{v.String(): true}
	for _, s := range all {
		if !seen[s.Version.String()] {
			seen[s.Version.String()] = true
			others = append(others, fmt.Sprintf("the %s shows %s", s.Source, s.Version))
		}
	}
	if len(others) == 0 {
		return ""
	}
	return " Sources disagree: " + strings.Join(others, " and ") + ". More than one PHP serves the site, or some workers were not restarted."
}

// SourceBackport reports a branch for which the PHP security team published a minimal source backport.
func (v Version) SourceBackport() bool {
	return v.Major == 7 && v.Minor == 4 || v.Major == 8 && v.Minor <= 1
}
