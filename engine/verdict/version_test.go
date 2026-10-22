package verdict

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		poweredBy, server string
		want              string
		distro            string
		standing          Branch
	}{
		{"PHP/8.5.11", "Apache/2.4.69 (Debian)", "8.5.11", "debian", BranchAffected},
		{"PHP/8.5.12", "", "8.5.12", "", BranchFixed},
		{"PHP/8.4.27", "", "8.4.27", "", BranchFixed},
		{"PHP/8.3.6-0ubuntu0.24.04.13", "", "8.3.6", "ubuntu", BranchAffected},
		{"PHP/8.1.2-1ubuntu2.28", "", "8.1.2", "ubuntu", BranchEOL},
		{"PHP/7.4.33-1+deb11u5", "", "7.4.33", "debian", BranchEOL},
		{"PHP/8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "", "8.3.36", "sury", BranchFixed},
		{"", "Apache/2.4.57 (Rocky Linux) PHP/8.2.13", "8.2.13", "redhat", BranchAffected},
		{"PHP/9.0.0", "", "9.0.0", "", BranchUnknown},
		{"PHP/5.6.40", "", "5.6.40", "", BranchEOL},
	}
	for _, c := range cases {
		v, ok := ParseVersion(c.poweredBy, c.server)
		if !ok {
			t.Errorf("%q %q: no version", c.poweredBy, c.server)
			continue
		}
		if v.String() != c.want || v.Distro != c.distro || v.Standing() != c.standing {
			t.Errorf("%q %q: got %s %q %s, want %s %q %s", c.poweredBy, c.server,
				v, v.Distro, v.Standing(), c.want, c.distro, c.standing)
		}
	}
	for _, header := range []string{"", "ASP.NET", "PHP", "PHP/8", "PHP/8.3", "Apache/2.4.69 (Debian)"} {
		if _, ok := ParseVersion(header, header); ok {
			t.Errorf("%q read as a version", header)
		}
	}
}

func TestBackports(t *testing.T) {
	ubuntu, _ := ParseVersion("PHP/8.3.6-0ubuntu0.24.04.13", "")
	debian, _ := ParseVersion("PHP/8.4.24", "Apache (Debian)")
	debianEOL, _ := ParseVersion("PHP/7.4.33-1+deb11u5", "")
	upstream, _ := ParseVersion("PHP/8.4.24", "")
	if !ubuntu.Backports() || debian.Backports() || !debianEOL.Backports() || upstream.Backports() {
		t.Error("backport rule: ubuntu always, debian on EOL branches only, upstream never")
	}
}
