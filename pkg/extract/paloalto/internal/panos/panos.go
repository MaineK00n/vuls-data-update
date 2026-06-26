// Package panos interprets Palo Alto PAN-OS affected-version data into
// contiguous affected intervals. It is shared by the paloalto json and list
// extractors, which translate their respective raw formats into a Stanza and
// call StanzaIntervals.
package panos

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	panosVersion "github.com/MaineK00n/go-paloalto-version/pan-os"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

// Stanza is one PAN-OS affected entry: a base version, an optional upper bound,
// and per-line status-change events. Both the json (versions[]) and list
// (version/affected/fixed) raw formats map onto it.
type Stanza struct {
	Status  string
	Version string
	// LessThan and LessThanOrEqual are mutually exclusive (CVE 5.0 version
	// object); at most one is non-empty. StanzaIntervals rejects a stanza that
	// sets both.
	LessThan        string
	LessThanOrEqual string
	Changes         []Change
}

// Change is one status-change event (a versions[].changes[] entry in json, or a
// single affected/fixed bound token in list).
type Change struct {
	At     string
	Status string
}

// Interval is one contiguous affected version interval. Fixed lists the release
// that closes the interval when that release is an actual fix.
type Interval struct {
	GE, GT, LE, LT string
	Fixed          []string
}

// transitionPriority decides which transition wins when several are generated
// for the same version (higher wins). In particular a maintenance line's own
// pre-first-change status (priorityLineStart) must beat the neighbouring line's
// revert marker (priorityLineEnd) placed on the same version.
type transitionPriority int

const (
	// priorityLineEnd: the previous maintenance line's end reverting to the
	// base-timeline status.
	priorityLineEnd transitionPriority = iota + 1
	// priorityLineStart: a maintenance line's own start segment.
	priorityLineStart
	// priorityStanzaBound: the stanza's own start version or upper bound.
	priorityStanzaBound
	// priorityChangeEvent: an explicit changes[] event.
	priorityChangeEvent
)

// transition is a status switch point on the version timeline.
type transition struct {
	affected bool
	// fix marks transitions that originate from an explicit "unaffected"
	// change (or a concrete lessThan release), i.e. an actual fix release —
	// as opposed to line boundaries where the status merely reverts.
	fix bool
	// priority resolves collisions when several transitions land on the same
	// version (see transitionPriority).
	priority transitionPriority
}

// StanzaIntervals interprets one PAN-OS stanza into affected version intervals.
//
// PAN-OS maintains maintenance lines (X.Y.Z) in parallel and backports fixes
// as hotfixes (X.Y.Z-hN), which PAN expresses through changes[] entries. The
// CVE 5.0 "status persists until the next change" reading breaks down on this
// data (e.g. CVE-2024-0012 lists 11.1.1 as affected although a strict reading
// of "11.1.0-h4: unaffected" would cover it), so the interpretation here is:
//
//   - a change at a base release (X.Y.Z) switches the status timeline across
//     maintenance lines (vulnerability introduced / fixed), e.g.
//     CVE-2024-3393 "10.2.8: affected", "10.2.14: unaffected"
//   - a change at a hotfix (X.Y.Z-hN) acts only within its maintenance line:
//     the segment before the line's first change takes the negated status of
//     that change, and at the next base release the timeline reverts to the
//     base status (verified against x_affectedList of CVE-2024-0012,
//     CVE-2024-3393 and CVE-2025-4619)
//
// A timeline that would end "affected" without an explicit upper bound is
// clamped at the highest version any event refers to (the data never means
// open-ended; e.g. the trailing lines of CVE-2026-0227 stanzas).
//
// Return contract: an empty/nil slice means "nothing affected here" (no
// criterion). A single zero-value interval (all bounds empty) means "every
// version affected" — it maps to a bare CPE criterion with no Range. These two
// are distinct, so callers must not collapse nil and []Interval{{}}.
func StanzaIntervals(stanza Stanza) ([]Interval, error) {
	affected, err := statusToBool(stanza.Status)
	if err != nil {
		return nil, errors.Wrapf(err, "parse status %q", stanza.Status)
	}

	start, defaultUpper, all, err := parseVersionExpr(stanza.Version)
	if err != nil {
		return nil, errors.Wrapf(err, "parse version %q", stanza.Version)
	}

	if all {
		switch {
		case stanza.LessThan != "" || stanza.LessThanOrEqual != "" || len(stanza.Changes) > 0:
			return nil, errors.Errorf("version is %q, but lessThan, lessThanOrEqual or changes is set", stanza.Version)
		case affected:
			// "All" versions affected: one interval with every bound empty.
			// This is deliberately a single zero-value element, NOT nil — an
			// empty-bounds interval becomes a bare CPE criterion (Range == nil)
			// that matches every PAN-OS version, whereas nil (below) means no
			// interval and hence no criterion. See the return contract above.
			return []Interval{{}}, nil
		default:
			// "All" but unaffected: nothing is affected, so no interval.
			return nil, nil
		}
	}

	// lessThan and lessThanOrEqual are mutually exclusive in the CVE 5.0
	// version object. Reject a stanza that sets both rather than silently
	// dropping lessThanOrEqual in the switch below.
	if stanza.LessThan != "" && stanza.LessThanOrEqual != "" {
		return nil, errors.Errorf("both lessThan %q and lessThanOrEqual %q are set", stanza.LessThan, stanza.LessThanOrEqual)
	}

	var (
		upper          *panosVersion.Version
		upperInclusive bool
		upperIsRelease bool
	)
	// Resolve the upper bound by priority: an explicit lessThan / lessThanOrEqual
	// (mutually exclusive, guarded above) wins; otherwise fall back to the
	// series-implied bound (defaultUpper, e.g. "8.0.*" -> 8.1.0). defaultUpper is
	// NOT exclusive with the explicit bounds — it is the lowest-priority default.
	switch {
	case stanza.LessThan != "":
		v, isRelease, err := parseBoundExpr(stanza.LessThan, start)
		if err != nil {
			return nil, errors.Wrapf(err, "parse lessThan %q", stanza.LessThan)
		}
		upper, upperIsRelease = v, isRelease
	case stanza.LessThanOrEqual != "":
		v, isRelease, err := parseBoundExpr(stanza.LessThanOrEqual, start)
		if err != nil {
			return nil, errors.Wrapf(err, "parse lessThanOrEqual %q", stanza.LessThanOrEqual)
		}
		switch {
		case isRelease:
			upper, upperInclusive = v, true
		default:
			// Non-concrete forms (e.g. "8.1*") already denote an exclusive
			// next-release bound.
			upper = v
		}
	default:
		// No explicit bound: fall back to the series-implied bound, which is
		// nil for non-series forms (leaving upper unset).
		upper = defaultUpper
	}

	type event struct {
		v        panosVersion.Version
		affected bool
	}
	events := make([]event, 0, len(stanza.Changes))
	for _, c := range stanza.Changes {
		a, err := statusToBool(c.Status)
		if err != nil {
			return nil, errors.Wrapf(err, "parse change status %q", c.Status)
		}
		// at occasionally lists several versions at once
		// (CVE-2019-17440: "9.0.6, 9.0.5-h3").
		for at := range strings.SplitSeq(c.At, ",") {
			v, err := parseVersion(at)
			if err != nil {
				return nil, errors.Wrapf(err, "parse change at %q", c.At)
			}
			events = append(events, event{v: v, affected: a})
		}
	}

	// A hotfix-level lessThan is the first maintenance line's fix, not the
	// stanza's overall end (e.g. CVE-2024-3400: lessThan 10.2.0-h3 while
	// changes carry fixes through 10.2.9-h1, with the lines in between fully
	// affected). When changes exist, fold it into them as a line-scoped fix
	// instead of treating it as a cross-line boundary.
	if len(events) > 0 && upper != nil && !upperInclusive && upper.Hotfix != nil {
		if !slices.ContainsFunc(events, func(e event) bool { return e.v.Compare(*upper) == 0 }) {
			events = append(events, event{v: *upper, affected: false})
		}
		upper, upperIsRelease = nil, false
	}

	if len(events) == 0 {
		switch {
		case !affected:
			// "unaffected <X.Y.Z> lessThan <X.Y*>" implies the series was
			// affected before the fix release: emit the complement
			// [X.Y.0, X.Y.Z) (e.g. PAN-SA-2015-0006 "unaffected 7.0.2,
			// lessThan 7.0*").
			if start != nil && upper != nil && !upperInclusive && !upperIsRelease &&
				upper.Compare(panosVersion.Version{Major: start.Major, Minor: start.Minor + 1}) == 0 {
				seriesStart := panosVersion.Version{Major: start.Major, Minor: start.Minor}
				if seriesStart.Compare(*start) < 0 {
					return []Interval{{GE: seriesStart.String(), LT: start.String(), Fixed: []string{start.String()}}}, nil
				}
			}
			return nil, nil
		case start == nil && upper == nil:
			// No version and no bound (e.g. version "None"/"" with no
			// lessThan/lessThanOrEqual): no constraint, so nothing to detect.
			return nil, nil
		case upper == nil:
			switch start.Hotfix {
			case nil:
				// A bare release with no upper bound means the series from
				// that release on (e.g. CVE-2020-2035 lists "8.1.0" .. "10.1.0"
				// stanzas only, while x_affectedList enumerates the whole
				// series).
				return []Interval{{GE: start.String(), LT: panosVersion.Version{Major: start.Major, Minor: start.Minor + 1}.String()}}, nil
			default:
				// A single concrete hotfix release.
				return []Interval{{GE: start.String(), LE: start.String()}}, nil
			}
		default:
			i := Interval{}
			if start != nil {
				i.GE = start.String()
			}
			switch {
			case upperInclusive:
				i.LE = upper.String()
			default:
				i.LT = upper.String()
				if upperIsRelease {
					i.Fixed = []string{upper.String()}
				}
			}
			return []Interval{i}, nil
		}
	}

	// Transition timeline. Build base-level transitions first so that
	// baseStatusAt can answer "what is the cross-line status at version v".
	transitions := map[string]transition{}
	versions := map[string]panosVersion.Version{}
	add := func(v panosVersion.Version, t transition) {
		k := v.String()
		if existing, ok := transitions[k]; ok && existing.priority >= t.priority {
			return
		}
		transitions[k] = t
		versions[k] = v
	}

	if start != nil {
		add(*start, transition{affected: affected, priority: priorityStanzaBound})
	}
	if upper != nil && !upperInclusive {
		// Explicit EXCLUSIVE upper bound; an event at the same version wins (it
		// carries the real status). For affected stanzas the concrete bound is
		// the fix release.
		//
		// An inclusive bound (lessThanOrEqual) is deliberately NOT added as a
		// transition here: its switch to unaffected is at the NEXT version, not
		// at the bound itself. PAN's data always pairs a lessThanOrEqual with a
		// redundant change at bound+1 (status "unaffected") — e.g. version "5.0"
		// lessThanOrEqual "5.0.19" with changes[]{at: "5.0.20", unaffected} —
		// which supplies that closing transition, so the interval still ends
		// exactly at the inclusive cap. The inclusive bound additionally feeds
		// updateClamp below (bound.maintenance+1), which would close an
		// affected-ending timeline; such a timeline cannot arise from this data
		// (every lessThanOrEqual change is "unaffected" at bound+1).
		add(*upper, transition{affected: false, fix: upperIsRelease && affected, priority: priorityStanzaBound})
	}

	baseEvents := make([]event, 0, len(events))
	for _, e := range events {
		add(e.v, transition{affected: e.affected, fix: !e.affected, priority: priorityChangeEvent})
		if e.v.Hotfix == nil {
			baseEvents = append(baseEvents, e)
		}
	}

	// Cross-line status timeline: the stanza's start / upper bound plus
	// base-release events.
	type baseTransition struct {
		v        panosVersion.Version
		affected bool
	}
	bs := make([]baseTransition, 0, len(baseEvents)+2)
	if start != nil {
		bs = append(bs, baseTransition{v: *start, affected: affected})
	}
	if upper != nil && !upperInclusive {
		bs = append(bs, baseTransition{v: *upper, affected: false})
	}
	for _, e := range baseEvents {
		bs = append(bs, baseTransition(e))
	}
	slices.SortStableFunc(bs, func(a, b baseTransition) int { return a.v.Compare(b.v) })
	baseStatusAt := func(v panosVersion.Version) bool {
		st := start == nil && affected
		for _, b := range bs {
			if b.v.Compare(v) <= 0 {
				st = b.affected
			}
		}
		return st
	}

	// Per-maintenance-line boundaries for hotfix-level events.
	lines := map[string][]event{}
	for _, e := range events {
		if e.v.Hotfix == nil {
			continue
		}
		k := panosVersion.Version{Major: e.v.Major, Minor: e.v.Minor, Maintenance: e.v.Maintenance}.String()
		lines[k] = append(lines[k], e)
	}
	var clamp *panosVersion.Version
	updateClamp := func(v panosVersion.Version) {
		if clamp == nil || clamp.Compare(v) < 0 {
			clamp = &v
		}
	}
	if upper != nil {
		switch {
		case upperInclusive:
			updateClamp(panosVersion.Version{Major: upper.Major, Minor: upper.Minor, Maintenance: upper.Maintenance + 1})
		default:
			updateClamp(*upper)
		}
	}
	for k, es := range lines {
		lineStart, err := panosVersion.NewVersion(k)
		if err != nil {
			return nil, errors.Wrapf(err, "parse line %q", k)
		}
		lineEnd := panosVersion.Version{Major: lineStart.Major, Minor: lineStart.Minor, Maintenance: lineStart.Maintenance + 1}
		updateClamp(lineEnd)

		slices.SortStableFunc(es, func(a, b event) int { return a.v.Compare(b.v) })
		add(lineStart, transition{affected: !es[0].affected, priority: priorityLineStart})
		add(lineEnd, transition{affected: baseStatusAt(lineEnd), priority: priorityLineEnd})
	}
	for _, e := range baseEvents {
		updateClamp(panosVersion.Version{Major: e.v.Major, Minor: e.v.Minor, Maintenance: e.v.Maintenance + 1})
	}

	ks := slices.Collect(maps.Keys(versions))
	slices.SortFunc(ks, func(a, b string) int { return versions[a].Compare(versions[b]) })

	var (
		is      []Interval
		current = start == nil && affected
		open    *string
	)
	if current {
		open = new(string) // unbounded start
	}
	for _, k := range ks {
		t := transitions[k]
		if t.affected == current {
			continue
		}
		switch {
		case t.affected:
			v := versions[k].String()
			open = &v
		default:
			i := Interval{GE: *open, LT: versions[k].String()}
			if t.fix {
				i.Fixed = []string{versions[k].String()}
			}
			is = append(is, i)
			open = nil
		}
		current = t.affected
	}
	if open != nil {
		// The timeline would end "affected": close it at the highest version
		// the stanza refers to — the data never means open-ended (e.g. the
		// trailing line-end reverts of CVE-2026-0227 stanzas).
		switch clamp {
		case nil:
			is = append(is, Interval{GE: *open})
		default:
			if v, err := parseVersion(*open); err != nil || v.Compare(*clamp) < 0 {
				is = append(is, Interval{GE: *open, LT: clamp.String()})
			}
		}
	}
	return is, nil
}

func statusToBool(s string) (bool, error) {
	switch s {
	case "affected":
		return true, nil
	case "unaffected":
		return false, nil
	default:
		return false, errors.Errorf("unexpected status. expected: %q, actual: %q", []string{"affected", "unaffected"}, s)
	}
}

var noDashHotfixPattern = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)[hH]([0-9]+)$`)

// parseVersion parses a concrete PAN-OS version, tolerating the irregularities
// present in the raw data: surrounding spaces, a trailing dot ("6.1.2."), a
// missing maintenance part ("9.1"), an uppercase or dash-less hotfix
// ("7.0.5H2").
func parseVersion(s string) (panosVersion.Version, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if m := noDashHotfixPattern.FindStringSubmatch(s); m != nil {
		s = fmt.Sprintf("%s-h%s", m[1], m[2])
	}
	if ss := strings.Split(s, "."); len(ss) == 2 {
		s = fmt.Sprintf("%s.0", s)
	}
	return panosVersion.NewVersion(s)
}

// parseVersionExpr parses the version field of a PAN-OS stanza. It returns the
// inclusive start (nil: unbounded), the implied exclusive upper bound for
// series forms ("X.Y.*", "X.Y All"; nil: none), and whether the expression
// means all versions.
func parseVersionExpr(s string) (start, defaultUpper *panosVersion.Version, all bool, err error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "None" || s == "unspecified":
		// "None"/"unspecified" carry no start; lessThan / lessThanOrEqual
		// hold the actual constraint.
		return nil, nil, false, nil
	case s == "All":
		return nil, nil, true, nil
	case strings.HasSuffix(s, " None"):
		// "<major>.<minor> None": no version of the series is concerned;
		// nothing to start an interval from.
		return nil, nil, false, nil
	case strings.HasSuffix(s, " All"), strings.HasSuffix(s, ".*"), strings.HasSuffix(s, "*"):
		base := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(s, " All"), ".*"), "*"))
		major, minor, err := parseMajorMinor(base)
		if err != nil {
			return nil, nil, false, errors.Wrapf(err, "parse series %q", s)
		}
		return &panosVersion.Version{Major: major, Minor: minor}, &panosVersion.Version{Major: major, Minor: minor + 1}, false, nil
	default:
		v, err := parseVersion(s)
		if err != nil {
			return nil, nil, false, errors.Wrapf(err, "parse version %q", s)
		}
		return &v, nil, false, nil
	}
}

// parseBoundExpr parses the lessThan / lessThanOrEqual field of a PAN-OS stanza
// into a version bound. isRelease reports whether the bound is a concrete
// release (and thus a fix candidate) rather than a derived series boundary.
func parseBoundExpr(s string, start *panosVersion.Version) (bound *panosVersion.Version, isRelease bool, err error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "All":
		if start == nil {
			return nil, false, errors.Errorf("version is empty although bound is %q", s)
		}
		return &panosVersion.Version{Major: start.Major, Minor: start.Minor + 1}, false, nil
	case strings.HasSuffix(s, "*"):
		// "9.1*" / "9.1.*": the whole series is within the bound; the
		// exclusive bound is the next series.
		major, minor, err := parseMajorMinor(strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(s, "*"), ".")))
		if err != nil {
			return nil, false, errors.Wrapf(err, "parse series %q", s)
		}
		return &panosVersion.Version{Major: major, Minor: minor + 1}, false, nil
	default:
		if major, minor, err := parseMajorMinor(s); err == nil {
			// A bare "<major>.<minor>" bound covers the whole series.
			return &panosVersion.Version{Major: major, Minor: minor + 1}, false, nil
		}
		v, err := parseVersion(s)
		if err != nil {
			return nil, false, errors.Wrapf(err, "parse bound %q", s)
		}
		return &v, true, nil
	}
}

func parseMajorMinor(s string) (major, minor int, err error) {
	ss, err := util.Split(s, ".")
	if err != nil {
		return 0, 0, errors.Wrapf(err, "split %q into <major>.<minor>", s)
	}
	major, err = strconv.Atoi(ss[0])
	if err != nil {
		return 0, 0, errors.Wrap(err, "parse major version")
	}
	minor, err = strconv.Atoi(ss[1])
	if err != nil {
		return 0, 0, errors.Wrap(err, "parse minor version")
	}
	return major, minor, nil
}
