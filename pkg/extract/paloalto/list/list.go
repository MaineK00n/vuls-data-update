package list

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/paloalto/internal/panos"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	paloaltoList "github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/list"
)

const source = "security.paloaltonetworks.com"

type options struct {
	dir string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "paloalto", "list"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Palo Alto Networks List")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched paloaltoList.Advisory
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		if err := util.Write(filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.PaloAltoList,
		Name: new("Palo Alto Networks Security Advisories List"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

func extract(fetched paloaltoList.Advisory, raws []string) (dataTypes.Data, error) {
	ds, err := detections(fetched)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "detections")
	}

	data := dataTypes.Data{
		ID:         dataTypes.RootID(fetched.ID),
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.PaloAltoList,
			Raws: raws,
		},
	}

	// The list source carries no CVSS vector/score, CWE, references or CAPEC —
	// only a qualitative vendor severity. Content placement mirrors the json
	// extractor: a PAN-SA-* root is an advisory, a CVE-* root is a vulnerability
	// (with a bare pointer advisory when the title names a PAN-SA grouping).
	if strings.HasPrefix(fetched.ID, "PAN-SA-") {
		data.Advisories = []advisoryTypes.Advisory{{
			Content:  advisoryContent(advisoryContentTypes.AdvisoryID(fetched.ID), fetched),
			Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
		}}
		return data, nil
	}

	data.Vulnerabilities = []vulnerabilityTypes.Vulnerability{{
		Content:  vulnerabilityContent(vulnerabilityContentTypes.VulnerabilityID(fetched.ID), fetched),
		Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
	}}
	if id := groupingAdvisoryID(fetched.Title); id != "" {
		data.Advisories = []advisoryTypes.Advisory{{
			Content:  advisoryContentTypes.Content{ID: advisoryContentTypes.AdvisoryID(id)},
			Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
		}}
	}
	return data, nil
}

func advisoryContent(id advisoryContentTypes.AdvisoryID, a paloaltoList.Advisory) advisoryContentTypes.Content {
	return advisoryContentTypes.Content{
		ID:          id,
		Title:       a.Title,
		Description: description(a.Problem),
		Severity:    severities(a),
		Mitigations: remediations(a.Solution),
		Workarounds: remediations(a.WorkAround),
		References:  []referenceTypes.Reference{{Source: source, URL: fmt.Sprintf("https://security.paloaltonetworks.com/%s", a.ID)}},
		Published:   parseTime(a.Date),
		Modified:    parseTime(a.Updated),
	}
}

func vulnerabilityContent(id vulnerabilityContentTypes.VulnerabilityID, a paloaltoList.Advisory) vulnerabilityContentTypes.Content {
	return vulnerabilityContentTypes.Content{
		ID:          id,
		Title:       a.Title,
		Description: description(a.Problem),
		Severity:    severities(a),
		Mitigations: remediations(a.Solution),
		Workarounds: remediations(a.WorkAround),
		References:  []referenceTypes.Reference{{Source: source, URL: fmt.Sprintf("https://security.paloaltonetworks.com/%s", a.ID)}},
		Published:   parseTime(a.Date),
		Modified:    parseTime(a.Updated),
	}
}

// severities returns the qualitative severity as a vendor severity. The list
// source provides no usable CVSS score or vector (base_score is always 0 and no
// vector string is present), so no CVSS severity is emitted.
func severities(a paloaltoList.Advisory) []severityTypes.Severity {
	if a.Severity == "" {
		return nil
	}
	return []severityTypes.Severity{{
		Type:   severityTypes.SeverityTypeVendor,
		Source: source,
		Vendor: &a.Severity,
	}}
}

type langValue = struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func description(ps []langValue) string {
	for _, p := range ps {
		if isEnglish(p.Lang) {
			return p.Value
		}
	}
	return ""
}

func remediations(ds []langValue) []remediationTypes.Remediation {
	var rs []remediationTypes.Remediation
	for _, d := range ds {
		if !isEnglish(d.Lang) || d.Value == "" {
			continue
		}
		rs = append(rs, remediationTypes.Remediation{Source: source, Description: d.Value})
	}
	return rs
}

// isEnglish mirrors the json extractor: Palo Alto mixes the ISO 639-1 "en" and
// ISO 639-2 "eng" codes (and the occasional "en-US"); an empty tag is English.
func isEnglish(lang string) bool {
	return lang == "" || lang == "en" || lang == "eng" || strings.HasPrefix(lang, "en-")
}

func parseTime(s string) *time.Time {
	return utiltime.Parse([]string{"2006-01-02T15:04:05.000Z", time.RFC3339Nano, time.RFC3339}, s)
}

// groupingAdvisoryID extracts a PAN-SA grouping ID from a CVE title that names
// it, e.g. "... (PAN-SA-2024-0015)". Most list titles do not carry it.
func groupingAdvisoryID(title string) string {
	_, rest, ok := strings.Cut(title, "(PAN-SA-")
	if !ok {
		return ""
	}
	id, _, ok := strings.Cut(rest, ")")
	if !ok {
		return ""
	}
	return "PAN-SA-" + id
}

func detections(a paloaltoList.Advisory) ([]detectionTypes.Detection, error) {
	var cns []criterionTypes.Criterion
	for i, line := range a.Version {
		affected := ""
		if i < len(a.Affected) {
			affected = a.Affected[i]
		}

		fixed := ""
		if i < len(a.Fixed) {
			fixed = a.Fixed[i]
		}

		stanza, ok := panosLineStanza(line, affected, fixed)
		if !ok {
			continue
		}

		is, err := panos.StanzaIntervals(stanza)
		if err != nil {
			return nil, errors.Wrapf(err, "interpret PAN-OS line %q affected %q fixed %q", line, affected, fixed)
		}
		for _, iv := range is {
			cns = append(cns, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					CPE:        ccTypes.CPE("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"),
					Range: func() *ccRangeTypes.Range {
						if iv.GE == "" && iv.GT == "" && iv.LE == "" && iv.LT == "" {
							return nil
						}
						return &ccRangeTypes.Range{
							Type:         ccRangeTypes.RangeTypePANOS,
							GreaterEqual: iv.GE,
							GreaterThan:  iv.GT,
							LessEqual:    iv.LE,
							LessThan:     iv.LT,
						}
					}(),
					Fixed: iv.Fixed,
				},
			})
		}
	}

	if len(cns) == 0 {
		return nil, nil
	}

	slices.SortFunc(cns, criterionTypes.Compare)
	cns = slices.CompactFunc(cns, func(x, y criterionTypes.Criterion) bool {
		return criterionTypes.Compare(x, y) == 0
	})

	return []detectionTypes.Detection{{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Conditions: []conditionTypes.Condition{{
			Criteria: criteriaTypes.Criteria{
				Operator:   criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: cns,
			},
		}},
	}}, nil
}

// panosLineStanza translates one list version/affected/fixed triple into a
// panos.Stanza. ok is false for lines this source cannot turn into a clean
// PAN-OS version range: non-PAN-OS products, "None"/empty affected, and prose /
// configuration conditions (e.g. "All without CTD inspection enabled on PA-800,
// …", which the json source represents cleanly and which serves as the primary
// source).
//
// The affected and fixed arrays together describe the timeline; each token is a
// status transition (deduped, since they are usually complementary, but for
// some records the affected start and the fix point live in different arrays —
// e.g. affected ">= 9.0.10" with fixed ">= 9.0.15"):
//
//	affected "< V"  / fixed ">= V" -> fixed at V      (change {V, unaffected})
//	affected ">= V" / fixed "< V"  -> affected from V (change {V, affected})
//
// Single-token forms are handled directly:
//
//	"<= V"                      -> affected through V (LessThanOrEqual)
//	"X.Y.*" / "All" / "X.Y All" -> whole series affected
//	bare "X.Y.Z"                -> that release on (json's bare-affected shape)
//
// The base status is "unaffected" when the vulnerability is introduced at a
// base release (first affected token ">= X.Y.Z"); a leading ">= X.Y.Z-hN" is a
// regression in an already-affected line, so the base stays affected. Platform
// qualifiers (" on Panorama", ...) are stripped. As a fallback source over
// messier text, an unrecognized token skips the line (ok=false); a
// recognized-but-malformed version still hard-errors via panos.StanzaIntervals.
func panosLineStanza(line, affected, fixed string) (panos.Stanza, bool) {
	ver, ok := panosLineVersion(line)
	if !ok {
		return panos.Stanza{}, false
	}

	tokens := splitTokens(affected)
	if len(tokens) == 0 {
		return panos.Stanza{}, false
	}

	if len(tokens) == 1 {
		t := tokens[0]
		switch {
		case t == "None" || strings.HasSuffix(t, " None"):
			return panos.Stanza{}, false
		case t == "All":
			return panos.Stanza{Status: "affected", Version: ver + " All"}, true
		case strings.HasSuffix(t, " All"), strings.HasSuffix(t, "*"):
			// "9.1 All" / "X.Y.*": the whole series is affected.
			return panos.Stanza{Status: "affected", Version: t}, true
		case strings.HasPrefix(t, "<="):
			return panos.Stanza{Status: "affected", Version: ver, LessThanOrEqual: versionToken(t[2:])}, true
		case t[0] >= '0' && t[0] <= '9':
			// A single bare version ("11.2.2"): that release on (json's
			// bare-affected shape, expanded by panos to [11.2.2, 11.3.0)).
			return panos.Stanza{Status: "affected", Version: versionToken(t)}, true
		}
	}

	stanza := panos.Stanza{Version: ver, Status: "affected"}
	if v, ok := strings.CutPrefix(tokens[0], ">="); ok && !strings.Contains(v, "-") {
		stanza.Status = "unaffected"
	}

	seen := map[string]struct{}{}
	addChange := func(at, status string) {
		c := panos.Change{At: versionToken(at), Status: status}
		k := c.At + " " + status
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		stanza.Changes = append(stanza.Changes, c)
	}

	for _, t := range tokens {
		switch {
		case strings.HasPrefix(t, ">="):
			addChange(t[2:], "affected")
		case strings.HasPrefix(t, "<"):
			addChange(t[1:], "unaffected")
		default:
			// Prose / configuration condition this source cannot express; the
			// json source carries these cleanly. Skip the line.
			return panos.Stanza{}, false
		}
	}
	// Merge the fixed bounds: complementary to affected for most records, but
	// some carry the fix point only here (affected ">= 9.0.10", fixed ">= 9.0.15").
	for _, t := range splitTokens(fixed) {
		switch {
		case strings.HasPrefix(t, ">="):
			addChange(t[2:], "unaffected")
		case strings.HasPrefix(t, "<"):
			addChange(t[1:], "affected")
		}
	}
	return stanza, true
}

// versionToken returns the leading version of an operator-stripped token,
// dropping any trailing footnote marker or note (e.g. "10.2.14 ¹" -> "10.2.14").
// PAN-OS versions contain no spaces, so cutting at the first space is safe.
func versionToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	return s
}

// splitTokens splits a comma-joined affected/fixed value into trimmed,
// platform-stripped, non-empty tokens.
func splitTokens(s string) []string {
	var tokens []string
	for t := range strings.SplitSeq(s, ",") {
		t = stripPlatform(strings.TrimSpace(t))
		if t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens
}

// panosLineVersion returns the X.Y(.Z) version of a "PAN-OS …" line and whether
// the line is a PAN-OS version line. Non-version PAN-OS products (e.g. "PAN-OS
// OpenConfig Plugin") and the bare "PAN-OS" return ok=false.
func panosLineVersion(line string) (string, bool) {
	line = strings.TrimSpace(line)
	rest, ok := strings.CutPrefix(line, "PAN-OS Firewall ")
	if !ok {
		rest, ok = strings.CutPrefix(line, "PAN-OS ")
		if !ok {
			return "", false
		}
	}
	rest = strings.TrimSpace(rest)
	// A version line starts with a digit (e.g. "11.1", "11.2.0"); anything else
	// (a product/plugin name) is not a PAN-OS version line.
	if rest == "" || rest[0] < '0' || rest[0] > '9' {
		return "", false
	}
	return rest, true
}

// stripPlatform removes a trailing " on <platform>" qualifier (e.g.
// " on Panorama", " on VM-Series") that list appends to some bounds.
func stripPlatform(s string) string {
	if i := strings.Index(s, " on "); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}
