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

// Reasons a site did not answer, in plain words.
const (
	FailedTimeout     = "the connection timed out"
	FailedRefused     = "the connection was refused"
	FailedReset       = "the connection was reset"
	FailedCertificate = "the site's TLS certificate was not accepted"
	FailedHandshake   = "the TLS handshake failed"
	FailedConnection  = "the connection failed"
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
	Failure           string // why the site did not answer, one of the Failed reasons
	PoweredBy         string
	Server            string
	PHPInfo           string // the version a phpinfo() page shows
	PHPInfoSettings   map[string]string
	Sightings         []Sighting // versions other pages showed
	Front             []string   // CDNs, firewalls and caches in front of the site
	Platforms         []string   // other platforms whose defaults the answers carry
	Hints             []string
	Oracle            Oracle
	OraclePaths       []string
	SessionBlocked    string // why a session request was refused
	// SessionUnclassified is set when session warnings arrived but no answer could be classified.
	SessionUnclassified bool
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
		return result(Unreachable, "low", "The site did not answer, so nothing was checked."+failureNote(in.Failure), nil)
	}
	out := judge(in)
	if in.Oracle == OraclePatched || in.Oracle == OracleUnpatched {
		out.Summary += sessionNote(in)
	}
	if out.Version != nil {
		out.Summary += disagreement(*out.Version, sightings(in))
	}
	// A block the summary already names needs no guess about the layer in front.
	genericBlock := out.Verdict == InspectionBlocked && strings.HasPrefix(in.InspectionBlocked, "HTTP ")
	if len(in.Front) > 0 && (out.Verdict == NoPHPSignal || out.Verdict == Inconclusive || genericBlock || in.Oracle == OracleSilent) {
		out.Summary += frontNote(in.Front)
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
		// An affected version keeps its framing; older behaviour argues against a backport.
		switch {
		case versioned && v.Standing() == BranchEOL:
			return judgeVersion(v, source, in)
		case versioned && v.Standing() == BranchAffected:
			return result(LikelyVulnerable, "medium", fmt.Sprintf("The %s shows %s; the fix is in %s.", source, v, v.FixedIn()), vp)
		}
		summary := "The session response suggests missing session-handling changes."
		if versioned && v.Standing() == BranchFixed {
			summary += fmt.Sprintf(" The %s shows %s; verify the running workers, the session extension and vendor patches because these observations conflict.", source, v)
		}
		return result(LikelyVulnerable, "medium", summary, vp)
	}
	if in.InspectionBlocked != "" {
		return result(InspectionBlocked, "low", fmt.Sprintf("Inspection was blocked (%s). The response does not establish the site's PHP patch state.", in.InspectionBlocked), vp)
	}
	if versioned {
		return judgeVersion(v, source, in)
	}
	if in.Oracle == OraclePatched {
		return result(Inconclusive, "low", "PHP session handling responded, but no PHP version or complete vendor patch status was established.", nil)
	}
	if len(in.Hints) > 0 {
		return result(Inconclusive, "low", fmt.Sprintf("PHP indicators were found (%s), but no PHP version was advertised.", strings.Join(in.Hints, ", "))+silentNote(in), nil)
	}
	if len(in.Platforms) > 0 {
		return result(NoPHPSignal, "low", "Nothing in the answers shows PHP; they point to "+strings.Join(in.Platforms, " and ")+" instead. Other paths on the host may still run PHP."+silentNote(in), nil)
	}
	return result(NoPHPSignal, "low", "Nothing in the answers shows PHP. A hardened PHP site looks the same."+silentNote(in), nil)
}

func sessionNote(in Input) string {
	where := "a tested path"
	if len(in.OraclePaths) > 0 {
		where = strings.Join(in.OraclePaths, ", ")
	}
	behaviour := "matched the session behaviour associated with the fix"
	if in.Oracle == OracleUnpatched {
		behaviour = "matched the older session behaviour"
	}
	return " Session handling on " + where + " " + behaviour + ". This observation does not establish a complete fix or exploitability for either CVE. CVE-2026-109618 is assessed from version evidence, not an OOM test."
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
	if in.SessionUnclassified {
		return " The session request returned PHP session warnings, but no answer could be classified: the response broke off, ended too close to the warnings, or was an error."
	}
	if in.SessionBlocked != "" {
		return " The session request was blocked (" + in.SessionBlocked + ")."
	}
	if reasons := hiding(in.PHPInfoSettings); len(reasons) > 0 {
		return " The session request showed nothing; the phpinfo() page shows " + strings.Join(reasons, " and ") + "."
	}
	return " The session request showed nothing: errors are hidden, upload progress is off, or the path does not reach PHP."
}

func result(verdict, confidence, summary string, v *Version) Result {
	return Result{Verdict: verdict, Confidence: confidence, Summary: summary, Version: v, Recommendations: recommendations[verdict]}
}

// frontNote says what a layer in front of the site can hide from a remote check.
func frontNote(layers []string) string {
	who, verb := strings.Join(layers, " and "), "answers"
	if len(layers) > 1 {
		verb = "answer"
	}
	return " " + strings.ToUpper(who[:1]) + who[1:] + " " + verb + " in front of the site and can replace headers, serve cached pages and filter requests, so this check sees less of the server behind it."
}

// failureNote names the reason, and a likely block where the network dropped the check.
func failureNote(reason string) string {
	if reason == "" {
		return ""
	}
	note := " " + strings.ToUpper(reason[:1]) + reason[1:] + "."
	switch reason {
	case FailedTimeout, FailedRefused, FailedReset:
		note += " If the site opens in a browser, its host may be blocking the checker's address."
	}
	return note
}
