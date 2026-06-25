package json

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/paloalto/internal/panos"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
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
	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	paloaltoJSON "github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/json"
)

// source is the fixed data-source label for Palo Alto records. The per-record
// containers.cna.providerMetadata is unreliable in this dataset (placeholder
// UUIDs, the literal "Not found", or the upstream CVE's original CNA), so a
// stable label is used for every content field — matching the repo convention
// (cisco-json "cisco.com", nvd "nvd.nist.gov") and the paloalto-list extractor.
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
		dir: filepath.Join(util.CacheDir(), "extract", "paloalto", "json"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Palo Alto Networks JSON")
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
		var fetched paloaltoJSON.CVE
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
		ID:   sourceTypes.PaloAltoJSON,
		Name: new("Palo Alto Networks Security Advisories JSON"),
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

func extract(fetched paloaltoJSON.CVE, raws []string) (dataTypes.Data, error) {
	if fetched.CVEMetadata.State != "PUBLISHED" {
		return dataTypes.Data{}, errors.Errorf("unexpected CVE state. expected: %q, actual: %q", []string{"PUBLISHED"}, fetched.CVEMetadata.State)
	}

	ds, err := detections(fetched)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "detections")
	}

	ss, err := severities(fetched)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "severities")
	}

	data := dataTypes.Data{
		ID:         dataTypes.RootID(fetched.CVEMetadata.CVEID),
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.PaloAltoJSON,
			Raws: raws,
		},
	}

	// The record is a Palo Alto Networks CNA advisory document. Its CNA
	// container (CVSS, title, description, CWE, ...) is placed on whichever
	// canonical entity matches the root ID's class:
	//   - a PAN-SA-* root is an advisory-class ID, so it becomes an Advisory
	//     carrying the full content (PAN-SA bundles do not structurally
	//     enumerate their member CVEs, so there are no Vulnerabilities)
	//   - a CVE-* root is the authoritative CVE record (Palo Alto is the CNA),
	//     so it becomes a Vulnerability carrying the full content; when the CVE
	//     is published under a PAN-SA grouping (source.advisory), a bare
	//     pointer Advisory records that membership
	if strings.HasPrefix(fetched.CVEMetadata.CVEID, "PAN-SA-") {
		data.Advisories = []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.CVEMetadata.CVEID),
				Title:       title(fetched),
				Description: description(fetched.Containers.CNA.Descriptions),
				Severity:    ss,
				CWE:         cwes(fetched),
				Mitigations: remediations(source, fetched.Containers.CNA.Solutions),
				Workarounds: remediations(source, fetched.Containers.CNA.Workarounds),
				References:  references(fetched),
				Published:   published(fetched),
				Modified:    modified(fetched),
			},
			Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
		}}
		return data, nil
	}

	data.Vulnerabilities = []vulnerabilityTypes.Vulnerability{{
		Content: vulnerabilityContentTypes.Content{
			ID:          vulnerabilityContentTypes.VulnerabilityID(fetched.CVEMetadata.CVEID),
			Title:       title(fetched),
			Description: description(fetched.Containers.CNA.Descriptions),
			Severity:    ss,
			CWE:         cwes(fetched),
			Mitigations: remediations(source, fetched.Containers.CNA.Solutions),
			Workarounds: remediations(source, fetched.Containers.CNA.Workarounds),
			References:  references(fetched),
			Published:   published(fetched),
			Modified:    modified(fetched),
		},
		Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
	}}
	if id := groupingAdvisoryID(fetched); id != "" {
		data.Advisories = []advisoryTypes.Advisory{{
			Content:  advisoryContentTypes.Content{ID: advisoryContentTypes.AdvisoryID(id)},
			Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
		}}
	}
	return data, nil
}

// groupingAdvisoryID returns the PAN-SA advisory the CVE is published under,
// taken verbatim from containers.cna.source.advisory. Unlike
// go-cve-dictionary, no "PAN-<CVE ID>" fallback is synthesized.
func groupingAdvisoryID(fetched paloaltoJSON.CVE) string {
	if m, ok := fetched.Containers.CNA.Source.(map[string]any); ok {
		if s, ok := m["advisory"].(string); ok && strings.HasPrefix(s, "PAN-SA-") {
			return s
		}
	}
	return ""
}

func title(fetched paloaltoJSON.CVE) string {
	if fetched.Containers.CNA.Title != nil {
		return *fetched.Containers.CNA.Title
	}
	return ""
}

// severities emits one Severity per CVSS version present. Palo Alto can publish
// several metrics of the same version for one CVE (one per metrics[].scenarios),
// so for each version the GENERAL scenario is preferred, otherwise the
// highest-base-score vector — e.g. CVE-2024-0012 carries two cvssV4_0 vectors
// and no GENERAL scenario, so the 9.3 vector is kept over the 5.9 one.
func severities(fetched paloaltoJSON.CVE) ([]severityTypes.Severity, error) {
	ms := fetched.Containers.CNA.Metrics
	var ss []severityTypes.Severity

	if i := selectMetric(ms, func(m paloaltoJSON.Metric) bool { return m.CVSSv2 != nil }, func(m paloaltoJSON.Metric) float64 { return m.CVSSv2.BaseScore }); i >= 0 {
		v2, err := v2Types.Parse(ms[i].CVSSv2.VectorString)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss v2 vector %q", ms[i].CVSSv2.VectorString)
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv2, Source: source, CVSSv2: v2})
	}
	if i := selectMetric(ms, func(m paloaltoJSON.Metric) bool { return m.CVSSv30 != nil }, func(m paloaltoJSON.Metric) float64 { return m.CVSSv30.BaseScore }); i >= 0 {
		v30, err := v30Types.Parse(ms[i].CVSSv30.VectorString)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss v3.0 vector %q", ms[i].CVSSv30.VectorString)
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv30, Source: source, CVSSv30: v30})
	}
	if i := selectMetric(ms, func(m paloaltoJSON.Metric) bool { return m.CVSSv31 != nil }, func(m paloaltoJSON.Metric) float64 { return m.CVSSv31.BaseScore }); i >= 0 {
		v31, err := v31Types.Parse(ms[i].CVSSv31.VectorString)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss v3.1 vector %q", ms[i].CVSSv31.VectorString)
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv31, Source: source, CVSSv31: v31})
	}
	if i := selectMetric(ms, func(m paloaltoJSON.Metric) bool { return m.CVSSv40 != nil }, func(m paloaltoJSON.Metric) float64 { return m.CVSSv40.BaseScore }); i >= 0 {
		v40, err := v40Types.Parse(ms[i].CVSSv40.VectorString)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss v4.0 vector %q", ms[i].CVSSv40.VectorString)
		}
		ss = append(ss, severityTypes.Severity{Type: severityTypes.SeverityTypeCVSSv40, Source: source, CVSSv40: v40})
	}
	return ss, nil
}

// isGeneralMetric reports whether a metric is the default "GENERAL" scenario.
func isGeneralMetric(m paloaltoJSON.Metric) bool {
	for _, s := range m.Scenarios {
		if s.Value == "GENERAL" {
			return true
		}
	}
	return false
}

// selectMetric picks, among the metrics carrying a given CVSS version (has), the
// one to emit: the GENERAL scenario when present, otherwise the highest base
// score. Returns -1 when no metric carries the version.
func selectMetric(ms []paloaltoJSON.Metric, has func(paloaltoJSON.Metric) bool, score func(paloaltoJSON.Metric) float64) int {
	best := -1
	for i, m := range ms {
		if !has(m) {
			continue
		}
		switch {
		case best == -1:
			best = i
		case isGeneralMetric(m) && !isGeneralMetric(ms[best]):
			best = i
		case isGeneralMetric(m) == isGeneralMetric(ms[best]) && score(m) > score(ms[best]):
			best = i
		}
	}
	return best
}

func cwes(fetched paloaltoJSON.CVE) []cweTypes.CWE {
	var cs []string
	for _, p := range fetched.Containers.CNA.ProblemTypes {
		for _, d := range p.Descriptions {
			if d.CweID != nil && strings.HasPrefix(*d.CweID, "CWE-") {
				cs = append(cs, *d.CweID)
			}
		}
	}
	if len(cs) == 0 {
		return nil
	}
	return []cweTypes.CWE{{
		Source: source,
		CWE:    util.Unique(cs),
	}}
}

func references(fetched paloaltoJSON.CVE) []referenceTypes.Reference {
	refs := make([]referenceTypes.Reference, 0, len(fetched.Containers.CNA.References))
	for _, r := range fetched.Containers.CNA.References {
		refs = append(refs, referenceTypes.Reference{
			Source: source,
			URL:    r.URL,
		})
	}
	return refs
}

// isEnglish reports whether a CVE-record lang tag denotes English. Palo Alto
// mixes the ISO 639-1 "en" and the ISO 639-2 "eng" codes (and the occasional
// "en-US"); an empty tag is treated as English too.
func isEnglish(lang string) bool {
	return lang == "" || lang == "en" || lang == "eng" || strings.HasPrefix(lang, "en-")
}

// description joins every English entry. Palo Alto frequently splits a record's
// description across several lang:"en" descriptions[] entries (e.g.
// CVE-2020-1968 has three, the trailing ones covering non-PAN-OS products not
// captured elsewhere), so taking only the first would silently drop content.
func description(ds []paloaltoJSON.Description) string {
	var vs []string
	for _, d := range ds {
		if isEnglish(d.Lang) && d.Value != "" {
			vs = append(vs, d.Value)
		}
	}
	return strings.Join(vs, "\n\n")
}

func remediations(source string, ds []paloaltoJSON.Description) []remediationTypes.Remediation {
	var rs []remediationTypes.Remediation
	for _, d := range ds {
		if !isEnglish(d.Lang) || d.Value == "" {
			continue
		}
		rs = append(rs, remediationTypes.Remediation{
			Source:      source,
			Description: d.Value,
		})
	}
	return rs
}

func published(fetched paloaltoJSON.CVE) *time.Time {
	if fetched.Containers.CNA.DatePublic != nil {
		if t := utiltime.Parse([]string{"2006-01-02T15:04:05.000Z", time.RFC3339Nano}, *fetched.Containers.CNA.DatePublic); t != nil {
			return t
		}
	}
	if fetched.CVEMetadata.DatePublished != nil {
		return utiltime.Parse([]string{"2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05", time.RFC3339Nano}, *fetched.CVEMetadata.DatePublished)
	}
	return nil
}

func modified(fetched paloaltoJSON.CVE) *time.Time {
	if fetched.CVEMetadata.DateUpdated != nil {
		return utiltime.Parse([]string{"2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05", time.RFC3339Nano}, *fetched.CVEMetadata.DateUpdated)
	}
	return nil
}

func detections(fetched paloaltoJSON.CVE) ([]detectionTypes.Detection, error) {
	var cns []criterionTypes.Criterion
	for _, a := range fetched.Containers.CNA.Affected {
		if a.Vendor == nil || *a.Vendor != "Palo Alto Networks" || a.Product == nil {
			continue
		}

		switch strings.TrimSpace(*a.Product) {
		case "PAN-OS", "PAN-OS Firewall":
			// Range criteria from versions[], interpreting changes as
			// per-maintenance-line backport fixes (see panosStanzaIntervals).
			for _, v := range a.Versions {
				// Known shapes that carry no detectable version range are
				// skipped here; anything else that fails to interpret falls
				// through to a hard error below so a new upstream anomaly cannot
				// pass unnoticed.
				if v.Status == "unknown" {
					// CVE 5.0 "unknown" impact: no affected range can be asserted.
					continue
				}
				// PAN-SA-2023-0004 stores GlobalProtect configuration
				// descriptions in the version field of "PAN-OS" affected entries.
				// Pinned to the exact advisory + wording so a new anomaly (a
				// different advisory or different text) still hard-errors.
				if fetched.CVEMetadata.CVEID == "PAN-SA-2023-0004" && strings.HasPrefix(v.Version, "with GlobalProtect") {
					continue
				}

				stanza := panos.Stanza{
					Status:  v.Status,
					Version: v.Version,
				}
				if v.LessThan != nil {
					stanza.LessThan = *v.LessThan
				}
				if v.LessThanOrEqual != nil {
					stanza.LessThanOrEqual = *v.LessThanOrEqual
				}
				for _, c := range v.Changes {
					stanza.Changes = append(stanza.Changes, panos.Change{At: c.At, Status: c.Status})
				}

				is, err := panos.StanzaIntervals(stanza)
				if err != nil {
					// An unrecognized shape is a new upstream anomaly: fail loud
					// (a warning would scroll past unnoticed in CI). Known
					// benign / anomalous shapes are skipped above; shapes with no
					// constraint yield no interval rather than an error.
					return nil, errors.Wrapf(err, "interpret PAN-OS affected version %q", stanza.Version)
				}
				for _, i := range is {
					cns = append(cns, criterionTypes.Criterion{
						Type: criterionTypes.CriterionTypeCPE,
						CPE: &ccTypes.Criterion{
							Vulnerable: true,
							CPE:        ccTypes.CPE("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"),
							Range: func() *ccRangeTypes.Range {
								// An interval with no bounds (the "All versions
								// affected" case) is a bare criterion: no Range,
								// matches every PAN-OS version.
								if i.GE == "" && i.GT == "" && i.LE == "" && i.LT == "" {
									return nil
								}
								return &ccRangeTypes.Range{
									Type:         ccRangeTypes.RangeTypePANOS,
									GreaterEqual: i.GE,
									GreaterThan:  i.GT,
									LessEqual:    i.LE,
									LessThan:     i.LT,
								}
							}(),
							Fixed: i.Fixed,
						},
					})
				}
			}
			// The PAN-OS cpes[] enumeration (present in 2024+ records) carries
			// the same affected set as versions[] expanded to hotfix
			// granularity, with the hotfix in the CPE update attribute. Keep
			// it verbatim as a separate enumeration criterion: it adds recall
			// for NVD-style "pan-os:<ver>:<hotfix>" queries and is inert for
			// queries that carry "<ver>-h<hotfix>" in the version attribute.
			cpes, err := validCPEs(fetched.CVEMetadata.CVEID, a.Cpes)
			if err != nil {
				return nil, errors.Wrapf(err, "valid cpes for %q", *a.Product)
			}
			if len(cpes) > 0 {
				cns = append(cns, criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &ccTypes.Criterion{
						Vulnerable: true,
						CPE:        ccTypes.CPE("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"),
						CPEMatches: cpes,
					},
				})
			}
		default:
			// Non-PAN-OS products: only the cpes[] enumeration is reliable
			// enough for detection (versions[] use product-specific version
			// schemes such as "6.2.8-h2 (6.2.8-c243)"). Same policy as
			// go-cve-dictionary. Products without cpes[] yield no criterion.
			cpes, err := validCPEs(fetched.CVEMetadata.CVEID, a.Cpes)
			if err != nil {
				return nil, errors.Wrapf(err, "valid cpes for %q", *a.Product)
			}
			for _, c := range cpes {
				cns = append(cns, criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &ccTypes.Criterion{
						Vulnerable: true,
						CPE:        c,
					},
				})
			}
		}
	}

	// Deduplicate: a record may repeat an identical affected stanza across
	// multiple affected entries (e.g. one per platform variant), which would
	// otherwise emit the same criterion twice into the OR list. Sort and drop
	// exact duplicates; order does not matter as util.Write re-sorts on output.
	slices.SortFunc(cns, criterionTypes.Compare)
	cns = slices.CompactFunc(cns, func(a, b criterionTypes.Criterion) bool {
		return criterionTypes.Compare(a, b) == 0
	})

	if len(cns) == 0 {
		return nil, nil
	}

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

// validCPEs filters cpes down to ones that bind as CPE 2.3 formatted strings;
// an unbindable CPE would make cpecriterion.Accept error at detect time, so it
// must not be emitted into criteria.
//
// The three known upstream typos are tolerated (skipped — the affected entry's
// other CPEs still produce criteria), each pinned to its CVE ID plus a
// distinctive substring of the specific malformation, so a different
// malformation hard-errors instead of passing unnoticed.
func validCPEs(id string, cpes []string) ([]ccTypes.CPE, error) {
	cs := make([]ccTypes.CPE, 0, len(cpes))
	for _, c := range cpes {
		if _, err := naming.UnbindFS(c); err != nil {
			switch {
			case id == "CVE-2025-4227" && strings.Contains(c, "Chrome OS"):
				// unescaped space in target_sw "Chrome OS", e.g.
				// cpe:2.3:a:palo_alto_networks:globalprotect_app:6.0.0:*:*:*:*:Chrome OS:*:*
			case id == "CVE-2024-3596" && strings.Contains(c, ":undefined:"):
				// CPE part is "undefined":
				// cpe:2.3:undefined:paloaltonetworks:palo_alto_networks_pan-os:9.1.7:-:*:*:*:*:*:*
			case id == "CVE-2025-4619" && strings.Contains(c, "palo_alto_networks:pan-os"):
				// extra trailing attribute field (13 components), e.g.
				// cpe:2.3:o:palo_alto_networks:pan-os:11.1.5:-:*:*:*:*:*:*:*
			default:
				return nil, errors.Wrapf(err, "unbind cpe %q", c)
			}
			continue
		}
		cs = append(cs, ccTypes.CPE(c))
	}
	if len(cs) == 0 {
		return nil, nil
	}
	return cs, nil
}
