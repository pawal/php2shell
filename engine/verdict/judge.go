package verdict

import (
	"fmt"
	"slices"
	"strings"
)

// Oracle is what the session-path request showed.
type Oracle string

const (
	OracleNotRun    Oracle = "not_run"
	OracleUnpatched Oracle = "unpatched_path"
	OraclePatched   Oracle = "patched_path"
	OracleSilent    Oracle = "silent"
)

// Verdict codes; they are part of the API and are never renamed.
const (
	Vulnerable         = "vulnerable"
	Patched            = "patched"
	LikelyVulnerable   = "likely_vulnerable"
	PossiblyBackported = "possibly_backported"
	EOLBranch          = "eol_branch"
	LikelyPatched      = "likely_patched"
	Inconclusive       = "inconclusive"
	NoPHPSignal        = "no_php_signal"
	Unreachable        = "unreachable"
	InspectionBlocked  = "inspection_blocked"
)

// Input is everything a verdict is drawn from.
type Input struct {
	InspectionBlocked string
	Reachable         bool
	PoweredBy         string
	Server            string
	PHPInfo           string // the version a phpinfo() page shows
	PHPInfoSettings   map[string]string
	Sightings         []Sighting // versions other pages showed
	Hints             []string
	Oracle            Oracle
}

// Result is the verdict with its grounds and what to do next.
type Result struct {
	Verdict         string   `json:"verdict"`
	Confidence      string   `json:"confidence"`
	Summary         string   `json:"summary"`
	Version         *Version `json:"php_version,omitempty"`
	Recommendations []string `json:"recommendations"`
}

// Judge applies the verdict matrix.
func Judge(in Input) Result {
	if !in.Reachable {
		return result(Unreachable, "low", "The site did not answer, so nothing was checked.", nil)
	}
	out := judge(in)
	if out.Version != nil {
		out.Summary += disagreement(*out.Version, sightings(in))
	}
	if in.PHPInfo != "" {
		advice := slices.Clone(out.Recommendations)
		if i := slices.Index(advice, Restart); i >= 0 {
			if restart := restartFor(in.PHPInfoSettings[ServerAPI]); restart != "" {
				advice[i] = restart
			}
		}
		out.Recommendations = append(advice, RemovePHPInfo)
	}
	return out
}

// judge draws the verdict from the version least likely to carry the fix.
func judge(in Input) Result {
	all := sightings(in)
	var v Version
	source, versioned := "", len(all) > 0
	if versioned {
		chosen := worst(all)
		v, source = chosen.Version, chosen.Source
	}
	var vp *Version
	if versioned {
		vp = &v
	}
	switch in.Oracle {
	case OracleUnpatched:
		summary := "PHP answered the session upload progress request the way only unpatched releases do."
		if versioned && v.Standing() == BranchFixed {
			summary += fmt.Sprintf(" The %s claims %s; the workers serving the site have not been restarted, the session extension is older than PHP itself, or another PHP answers.", source, v)
		}
		return result(Vulnerable, "high", summary, vp)
	case OraclePatched:
		summary := "PHP answered the session upload progress request the way patched releases do."
		if versioned && v.Standing() != BranchFixed {
			summary += fmt.Sprintf(" The %s shows %s, so the package carries a backported fix.", source, v)
		}
		return result(Patched, "high", summary, vp)
	}
	if in.InspectionBlocked != "" {
		return result(InspectionBlocked, "low", fmt.Sprintf("Inspection was blocked (%s). The response does not establish the site's PHP patch state.", in.InspectionBlocked), vp)
	}
	if versioned {
		return judgeVersion(v, source, in)
	}
	if len(in.Hints) > 0 {
		return result(Inconclusive, "low", fmt.Sprintf("PHP indicators were found (%s), but no PHP version was advertised.", strings.Join(in.Hints, ", "))+silentNote(in), nil)
	}
	return result(NoPHPSignal, "low", "Nothing in the answers shows PHP. A hardened PHP site looks the same."+silentNote(in), nil)
}

func judgeVersion(v Version, source string, in Input) Result {
	note := silentNote(in)
	switch v.Standing() {
	case BranchFixed:
		return result(LikelyPatched, "medium", fmt.Sprintf("The %s shows %s, which carries the fix.", source, v)+note, &v)
	case BranchAffected:
		if v.Backports() {
			return result(PossiblyBackported, "low", fmt.Sprintf("The %s shows %s from %s, which fixes releases without changing the version.", source, v, v.Distro)+note+measureNote(in), &v)
		}
		return result(LikelyVulnerable, "medium", fmt.Sprintf("The %s shows %s; the fix is in %s.", source, v, v.FixedIn())+note+measureNote(in), &v)
	case BranchEOL:
		summary := fmt.Sprintf("The %s shows %s, a branch the PHP project no longer fixes.", source, v)
		if v.Distro != "" {
			summary += " Only a vendor backport from " + v.Distro + " can carry the fix."
		}
		return result(EOLBranch, "medium", summary+note+measureNote(in), &v)
	}
	return result(Inconclusive, "low", fmt.Sprintf("The %s shows %s, a branch outside the advisory.", source, v)+note, &v)
}

func silentNote(in Input) string {
	if in.Oracle != OracleSilent {
		return ""
	}
	if reasons := hiding(in.PHPInfoSettings); len(reasons) > 0 {
		return " The session request showed nothing; the phpinfo() page shows " + strings.Join(reasons, " and ") + "."
	}
	return " The session request showed nothing: errors are hidden, upload progress is off, or the path does not reach PHP."
}

func result(verdict, confidence, summary string, v *Version) Result {
	return Result{Verdict: verdict, Confidence: confidence, Summary: summary, Version: v, Recommendations: recommendations[verdict]}
}
