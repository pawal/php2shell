package verdict

import (
	"fmt"
	"strings"
)

// shipped is a PHP release a distribution keeps and patches without renumbering.
type shipped struct {
	distro, vendor, release string
	pkg, notice             string // the package carrying the October fixes, and its advisory
	revisions               bool   // the release advertises its package revision
}

// frozen lists releases by the version they advertise, as of 19 November 2026.
var frozen = map[string]shipped{
	"8.5.9":  {"ubuntu", "Ubuntu", "Ubuntu 26.10", "8.5.9-0ubuntu2.1", "USN-8948-1", false},
	"8.5.4":  {"ubuntu", "Ubuntu", "Ubuntu 26.04", "8.5.4-0ubuntu1.5", "USN-8948-1", false},
	"8.3.6":  {"ubuntu", "Ubuntu", "Ubuntu 24.04", "8.3.6-0ubuntu0.24.04.13", "USN-8948-1", false},
	"8.1.2":  {"ubuntu", "Ubuntu", "Ubuntu 22.04", "8.1.2-1ubuntu2.28", "USN-8948-1", true},
	"7.4.3":  {"ubuntu", "Ubuntu", "Ubuntu 20.04", "7.4.3-4ubuntu2.29+esm5", "USN-8948-2", true},
	"7.2.24": {"ubuntu", "Ubuntu", "Ubuntu 18.04", "7.2.24-0ubuntu0.18.04.17+esm14", "USN-8948-2", true},
	"8.3.19": {"redhat", "Red Hat", "RHEL 10.0", "php-8.3.19-1.el10_0.2", "RHSA-2026:88561", false},
	"8.0.30": {"redhat", "Red Hat", "RHEL 9", "php-8.0.30-8.el9_8.1", "RHSA-2026:87151", false},
}

// shipped finds the distribution that ships this release, unless the version names another packager.
func (v Version) shipped() (shipped, bool) {
	s, ok := frozen[v.String()]
	if !ok || (v.Distro != "" && v.Distro != s.distro) {
		return shipped{}, false
	}
	return s, true
}

// revealsPackage reports a header whose package revision shows whether the October fixes are in.
func (v Version) revealsPackage() bool {
	s, ok := v.shipped()
	return ok && s.revisions && strings.HasPrefix(v.Suffix, "-")
}

// shippedNote names the package carrying the October fixes, and whether this build has it.
func shippedNote(v Version) string {
	s, ok := v.shipped()
	if !ok {
		return ""
	}
	note := fmt.Sprintf(" %s is the release %s ships; %s fixed CVE-2026-109618 and CVE-2026-109619 in %s (%s).", v, s.release, s.vendor, s.pkg, s.notice)
	if v.revealsPackage() {
		build := v.String() + v.Suffix
		if verrevcmp(v.Suffix[1:], s.pkg[strings.LastIndex(s.pkg, "-")+1:]) >= 0 {
			note += " This build, " + build + ", includes it."
		} else {
			note += " This build, " + build + ", is older and lacks those fixes."
		}
	}
	return note
}

// order ranks one character as dpkg does: tilde first, then the end, letters and the rest.
func order(s string) int {
	switch c := s[0]; {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func rank(s string) int {
	if s == "" {
		return 0
	}
	return order(s)
}

func isDigit(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

// verrevcmp compares two Debian version parts as dpkg does.
func verrevcmp(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a)) || (b != "" && !isDigit(b)) {
			if ac, bc := rank(a), rank(b); ac != bc {
				return ac - bc
			}
			a, b = a[1:], b[1:]
		}
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		first := 0
		for isDigit(a) && isDigit(b) {
			if first == 0 {
				first = int(a[0]) - int(b[0])
			}
			a, b = a[1:], b[1:]
		}
		if isDigit(a) {
			return 1
		}
		if isDigit(b) {
			return -1
		}
		if first != 0 {
			return first
		}
	}
	return 0
}
