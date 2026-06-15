package json

import (
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	panosVersion "github.com/MaineK00n/go-paloalto-version/pan-os"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

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
	exploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/exploit"
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

// panosCPE is the canonical PAN-OS CPE used for range-based criteria. It is
// the same WFN template go-cve-dictionary uses when interpreting PAN-OS
// affected entries.
const panosCPE = "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"

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
	switch fetched.CVEMetadata.State {
	case "PUBLISHED":
		return dataTypes.Data{
			ID: dataTypes.RootID(fetched.CVEMetadata.CVEID),
			Advisories: func() []advisoryTypes.Advisory {
				id := advisoryID(fetched)
				if id == "" {
					return nil
				}
				return []advisoryTypes.Advisory{{
					Content: advisoryContentTypes.Content{
						ID: advisoryContentTypes.AdvisoryID(id),
						Title: func() string {
							if fetched.Containers.CNA.Title != nil {
								return *fetched.Containers.CNA.Title
							}
							return ""
						}(),
						Description: description(fetched.Containers.CNA.Descriptions),
						References: []referenceTypes.Reference{{
							Source: getSource(fetched.Containers.CNA.ProviderMetadata),
							URL:    fmt.Sprintf("https://security.paloaltonetworks.com/%s", id),
						}},
						Published: published(fetched),
						Modified:  modified(fetched),
					},
					Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
				}}
			}(),
			Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(fetched.CVEMetadata.CVEID),
					Title: func() string {
						if fetched.Containers.CNA.Title != nil {
							return *fetched.Containers.CNA.Title
						}
						return ""
					}(),
					Description: description(fetched.Containers.CNA.Descriptions),
					Severity: func() []severityTypes.Severity {
						source := getSource(fetched.Containers.CNA.ProviderMetadata)
						var ss []severityTypes.Severity
						for _, metric := range fetched.Containers.CNA.Metrics {
							if metric.CVSSv2 != nil {
								v2, err := v2Types.Parse(metric.CVSSv2.VectorString)
								if err != nil {
									slog.Warn("unexpected CVSS v2 vector", slog.String("id", fetched.CVEMetadata.CVEID), slog.String("vector", metric.CVSSv2.VectorString))
									continue
								}
								ss = append(ss, severityTypes.Severity{
									Type:   severityTypes.SeverityTypeCVSSv2,
									Source: source,
									CVSSv2: v2,
								})
							}
							if metric.CVSSv30 != nil {
								v30, err := v30Types.Parse(metric.CVSSv30.VectorString)
								if err != nil {
									slog.Warn("unexpected CVSS v3.0 vector", slog.String("id", fetched.CVEMetadata.CVEID), slog.String("vector", metric.CVSSv30.VectorString))
									continue
								}
								ss = append(ss, severityTypes.Severity{
									Type:    severityTypes.SeverityTypeCVSSv30,
									Source:  source,
									CVSSv30: v30,
								})
							}
							if metric.CVSSv31 != nil {
								v31, err := v31Types.Parse(metric.CVSSv31.VectorString)
								if err != nil {
									slog.Warn("unexpected CVSS v3.1 vector", slog.String("id", fetched.CVEMetadata.CVEID), slog.String("vector", metric.CVSSv31.VectorString))
									continue
								}
								ss = append(ss, severityTypes.Severity{
									Type:    severityTypes.SeverityTypeCVSSv31,
									Source:  source,
									CVSSv31: v31,
								})
							}
							if metric.CVSSv40 != nil {
								v40, err := v40Types.Parse(metric.CVSSv40.VectorString)
								if err != nil {
									slog.Warn("unexpected CVSS v4.0 vector", slog.String("id", fetched.CVEMetadata.CVEID), slog.String("vector", metric.CVSSv40.VectorString))
									continue
								}
								ss = append(ss, severityTypes.Severity{
									Type:    severityTypes.SeverityTypeCVSSv40,
									Source:  source,
									CVSSv40: v40,
								})
							}
						}
						return ss
					}(),
					CWE: func() []cweTypes.CWE {
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
							Source: getSource(fetched.Containers.CNA.ProviderMetadata),
							CWE:    util.Unique(cs),
						}}
					}(),
					Mitigations: remediations(getSource(fetched.Containers.CNA.ProviderMetadata), fetched.Containers.CNA.Solutions),
					Workarounds: remediations(getSource(fetched.Containers.CNA.ProviderMetadata), fetched.Containers.CNA.Workarounds),
					Exploit: func() []exploitTypes.Exploit {
						var es []exploitTypes.Exploit
						for _, e := range fetched.Containers.CNA.Exploits {
							if (e.Lang != "" && e.Lang != "en") || e.Value == "" {
								continue
							}
							es = append(es, exploitTypes.Exploit{
								Source:      getSource(fetched.Containers.CNA.ProviderMetadata),
								Description: e.Value,
							})
						}
						return es
					}(),
					References: func() []referenceTypes.Reference {
						refs := make([]referenceTypes.Reference, 0, len(fetched.Containers.CNA.References))
						for _, r := range fetched.Containers.CNA.References {
							refs = append(refs, referenceTypes.Reference{
								Source: getSource(fetched.Containers.CNA.ProviderMetadata),
								URL:    r.URL,
							})
						}
						return refs
					}(),
					Published: published(fetched),
					Modified:  modified(fetched),
					Optional: func() map[string]any {
						m := make(map[string]any)
						// Preserve information that has no canonical field but is
						// still valuable: the raw affected products (incl. ones not
						// expressible as detection criteria), the enumerated
						// affected version list, CAPEC impacts, configuration
						// conditions and the source metadata.
						if len(fetched.Containers.CNA.Affected) > 0 {
							m["affected"] = fetched.Containers.CNA.Affected
						}
						if fetched.Containers.CNA.XAffectedList != nil {
							m["x_affectedList"] = fetched.Containers.CNA.XAffectedList
						}
						if len(fetched.Containers.CNA.Impacts) > 0 {
							m["impacts"] = fetched.Containers.CNA.Impacts
						}
						if len(fetched.Containers.CNA.Configurations) > 0 {
							m["configurations"] = fetched.Containers.CNA.Configurations
						}
						if fetched.Containers.CNA.Source != nil {
							m["source"] = fetched.Containers.CNA.Source
						}
						if len(m) == 0 {
							return nil
						}
						return m
					}(),
				},
				Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
			}},
			Detections: detections(fetched),
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.PaloAltoJSON,
				Raws: raws,
			},
		}, nil
	default:
		return dataTypes.Data{}, errors.Errorf("unexpected CVE state. expected: %q, actual: %q", []string{"PUBLISHED"}, fetched.CVEMetadata.State)
	}
}

// advisoryID returns the PAN-SA advisory ID for the record, taken verbatim
// from the raw data: the record ID itself for PAN-SA records, otherwise
// containers.cna.source.advisory when it is a PAN-SA ID. Unlike
// go-cve-dictionary, no "PAN-<CVE ID>" fallback is synthesized.
func advisoryID(fetched paloaltoJSON.CVE) string {
	if strings.HasPrefix(fetched.CVEMetadata.CVEID, "PAN-SA-") {
		return fetched.CVEMetadata.CVEID
	}
	if m, ok := fetched.Containers.CNA.Source.(map[string]any); ok {
		if s, ok := m["advisory"].(string); ok && strings.HasPrefix(s, "PAN-SA-") {
			return s
		}
	}
	return ""
}

func getSource(providerMetadata paloaltoJSON.ProviderMetadata) string {
	if providerMetadata.ShortName != nil {
		return *providerMetadata.ShortName
	}
	return providerMetadata.OrgID
}

func description(ds []paloaltoJSON.Description) string {
	for _, d := range ds {
		if d.Lang == "en" || strings.HasPrefix(d.Lang, "en-") {
			return d.Value
		}
	}
	return ""
}

func remediations(source string, ds []paloaltoJSON.Description) []remediationTypes.Remediation {
	var rs []remediationTypes.Remediation
	for _, d := range ds {
		if (d.Lang != "" && d.Lang != "en") || d.Value == "" {
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

func detections(fetched paloaltoJSON.CVE) []detectionTypes.Detection {
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
				stanza := panosStanza{
					status:  v.Status,
					version: v.Version,
				}
				if v.LessThan != nil {
					stanza.lessThan = *v.LessThan
				}
				if v.LessThanOrEqual != nil {
					stanza.lessThanOrEqual = *v.LessThanOrEqual
				}
				for _, c := range v.Changes {
					stanza.changes = append(stanza.changes, panosChange{at: c.At, status: c.Status})
				}

				is, err := panosStanzaIntervals(stanza)
				if err != nil {
					slog.Warn("failed to interpret PAN-OS affected version", slog.String("id", fetched.CVEMetadata.CVEID), slog.String("version", stanza.version), slog.String("lessThan", stanza.lessThan), slog.String("lessThanOrEqual", stanza.lessThanOrEqual), slog.String("err", err.Error()))
					continue
				}
				for _, i := range is {
					cns = append(cns, criterionTypes.Criterion{
						Type: criterionTypes.CriterionTypeCPE,
						CPE: &ccTypes.Criterion{
							Vulnerable: true,
							CPE:        ccTypes.CPE(panosCPE),
							Range: func() *ccRangeTypes.Range {
								if i.ge == "" && i.gt == "" && i.le == "" && i.lt == "" {
									return nil
								}
								return &ccRangeTypes.Range{
									Type:         ccRangeTypes.RangeTypePANOS,
									GreaterEqual: i.ge,
									GreaterThan:  i.gt,
									LessEqual:    i.le,
									LessThan:     i.lt,
								}
							}(),
							Fixed: i.fixed,
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
			if cpes := validCPEs(fetched.CVEMetadata.CVEID, a.Cpes); len(cpes) > 0 {
				cns = append(cns, criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &ccTypes.Criterion{
						Vulnerable: true,
						CPE:        ccTypes.CPE(panosCPE),
						CPEMatches: cpes,
					},
				})
			}
		default:
			// Non-PAN-OS products: only the cpes[] enumeration is reliable
			// enough for detection (versions[] use product-specific version
			// schemes such as "6.2.8-h2 (6.2.8-c243)"). Same policy as
			// go-cve-dictionary; the raw affected entry is preserved in
			// Optional["affected"].
			for _, c := range validCPEs(fetched.CVEMetadata.CVEID, a.Cpes) {
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

	if len(cns) == 0 {
		return nil
	}

	return []detectionTypes.Detection{{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Conditions: []conditionTypes.Condition{{
			Criteria: criteriaTypes.Criteria{
				Operator:   criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: cns,
			},
		}},
	}}
}

// validCPEs filters cpes down to ones that bind as CPE 2.3 formatted strings.
// Invalid entries (e.g. unescaped spaces in target_sw such as "Chrome OS")
// would make cpecriterion.Accept error at detect time, so they are skipped
// with a warning; the raw values remain available in Optional["affected"].
func validCPEs(id string, cpes []string) []ccTypes.CPE {
	cs := make([]ccTypes.CPE, 0, len(cpes))
	for _, c := range cpes {
		if _, err := naming.UnbindFS(c); err != nil {
			slog.Warn("invalid CPE", slog.String("id", id), slog.String("cpe", c))
			continue
		}
		cs = append(cs, ccTypes.CPE(c))
	}
	if len(cs) == 0 {
		return nil
	}
	return cs
}

type panosStanza struct {
	status          string
	version         string
	lessThan        string
	lessThanOrEqual string
	changes         []panosChange
}

type panosChange struct {
	at     string
	status string
}

// panosInterval is one contiguous affected version interval. fixed lists the
// release that closes the interval when that release is an actual fix.
type panosInterval struct {
	ge, gt, le, lt string
	fixed          []string
}

// panosTransition is a status switch point on the version timeline.
type panosTransition struct {
	affected bool
	// fix marks transitions that originate from an explicit "unaffected"
	// change (or a concrete lessThan release), i.e. an actual fix release —
	// as opposed to line boundaries where the status merely reverts.
	fix bool
	// priority decides which transition wins when several are generated for
	// the same version: explicit change events (4) > the stanza's own
	// start / upper bound (3) > a line's own start segment (2) > the
	// previous line's end reverting to the base status (1). In particular a
	// line's own pre-first-change status must beat the neighbouring line's
	// revert marker placed on the same version.
	priority int
}

// panosStanzaIntervals interprets one PAN-OS versions[] stanza into affected
// version intervals.
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
func panosStanzaIntervals(stanza panosStanza) ([]panosInterval, error) {
	affected, err := statusToBool(stanza.status)
	if err != nil {
		return nil, errors.Wrap(err, "parse status")
	}

	start, defaultUpper, all, err := parsePANOSVersionExpr(stanza.version)
	if err != nil {
		return nil, errors.Wrapf(err, "parse version %q", stanza.version)
	}

	if all {
		switch {
		case stanza.lessThan != "" || stanza.lessThanOrEqual != "" || len(stanza.changes) > 0:
			return nil, errors.Errorf("version is %q, but lessThan, lessThanOrEqual or changes is set", stanza.version)
		case affected:
			// All versions affected: a criterion without range narrowing.
			return []panosInterval{{}}, nil
		default:
			return nil, nil
		}
	}

	var (
		upper          *panosVersion.Version
		upperInclusive bool
		upperIsRelease bool
	)
	switch {
	case stanza.lessThan != "":
		v, isRelease, err := parsePANOSBoundExpr(stanza.lessThan, start)
		if err != nil {
			return nil, errors.Wrapf(err, "parse lessThan %q", stanza.lessThan)
		}
		upper, upperIsRelease = v, isRelease
	case stanza.lessThanOrEqual != "":
		v, isRelease, err := parsePANOSBoundExpr(stanza.lessThanOrEqual, start)
		if err != nil {
			return nil, errors.Wrapf(err, "parse lessThanOrEqual %q", stanza.lessThanOrEqual)
		}
		switch {
		case isRelease:
			upper, upperInclusive = v, true
		default:
			// Non-concrete forms (e.g. "8.1*") already denote an exclusive
			// next-release bound.
			upper = v
		}
	case defaultUpper != nil:
		upper = defaultUpper
	}

	type event struct {
		v        panosVersion.Version
		affected bool
	}
	events := make([]event, 0, len(stanza.changes))
	for _, c := range stanza.changes {
		a, err := statusToBool(c.status)
		if err != nil {
			return nil, errors.Wrapf(err, "parse change status %q", c.status)
		}
		// at occasionally lists several versions at once
		// (CVE-2019-17440: "9.0.6, 9.0.5-h3").
		for at := range strings.SplitSeq(c.at, ",") {
			v, err := parsePANOSVersion(at)
			if err != nil {
				return nil, errors.Wrapf(err, "parse change at %q", c.at)
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
					return []panosInterval{{ge: seriesStart.String(), lt: start.String(), fixed: []string{start.String()}}}, nil
				}
			}
			return nil, nil
		case start == nil && upper == nil:
			return nil, errors.Errorf("no version bounds. version: %q", stanza.version)
		case upper == nil:
			switch start.Hotfix {
			case nil:
				// A bare release with no upper bound means the series from
				// that release on (e.g. CVE-2020-2035 lists "8.1.0" .. "10.1.0"
				// stanzas only, while x_affectedList enumerates the whole
				// series).
				return []panosInterval{{ge: start.String(), lt: panosVersion.Version{Major: start.Major, Minor: start.Minor + 1}.String()}}, nil
			default:
				// A single concrete hotfix release.
				return []panosInterval{{ge: start.String(), le: start.String()}}, nil
			}
		default:
			i := panosInterval{}
			if start != nil {
				i.ge = start.String()
			}
			switch {
			case upperInclusive:
				i.le = upper.String()
			default:
				i.lt = upper.String()
				if upperIsRelease {
					i.fixed = []string{upper.String()}
				}
			}
			return []panosInterval{i}, nil
		}
	}

	// Transition timeline. Build base-level transitions first so that
	// baseStatusAt can answer "what is the cross-line status at version v".
	transitions := map[string]panosTransition{}
	versions := map[string]panosVersion.Version{}
	add := func(v panosVersion.Version, t panosTransition) {
		k := v.String()
		if existing, ok := transitions[k]; ok && existing.priority >= t.priority {
			return
		}
		transitions[k] = t
		versions[k] = v
	}

	if start != nil {
		add(*start, panosTransition{affected: affected, priority: 3})
	}
	if upper != nil && !upperInclusive {
		// Explicit upper bound; an event at the same version wins (it carries
		// the real status). For affected stanzas the concrete bound is the
		// fix release.
		add(*upper, panosTransition{affected: false, fix: upperIsRelease && affected, priority: 3})
	}

	baseEvents := make([]event, 0, len(events))
	for _, e := range events {
		add(e.v, panosTransition{affected: e.affected, fix: !e.affected, priority: 4})
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
		add(lineStart, panosTransition{affected: !es[0].affected, priority: 2})
		add(lineEnd, panosTransition{affected: baseStatusAt(lineEnd), priority: 1})
	}
	for _, e := range baseEvents {
		updateClamp(panosVersion.Version{Major: e.v.Major, Minor: e.v.Minor, Maintenance: e.v.Maintenance + 1})
	}

	ks := slices.Collect(maps.Keys(versions))
	slices.SortFunc(ks, func(a, b string) int { return versions[a].Compare(versions[b]) })

	var (
		is      []panosInterval
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
			i := panosInterval{ge: *open, lt: versions[k].String()}
			if t.fix {
				i.fixed = []string{versions[k].String()}
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
			is = append(is, panosInterval{ge: *open})
		default:
			if v, err := parsePANOSVersion(*open); err != nil || v.Compare(*clamp) < 0 {
				is = append(is, panosInterval{ge: *open, lt: clamp.String()})
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

var panosNoDashHotfixPattern = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)[hH]([0-9]+)$`)

// parsePANOSVersion parses a concrete PAN-OS version, tolerating the
// irregularities present in the raw data: surrounding spaces, a trailing dot
// ("6.1.2."), a missing maintenance part ("9.1"), an uppercase or dash-less
// hotfix ("7.0.5H2").
func parsePANOSVersion(s string) (panosVersion.Version, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if m := panosNoDashHotfixPattern.FindStringSubmatch(s); m != nil {
		s = fmt.Sprintf("%s-h%s", m[1], m[2])
	}
	if ss := strings.Split(s, "."); len(ss) == 2 {
		s = fmt.Sprintf("%s.0", s)
	}
	return panosVersion.NewVersion(s)
}

// parsePANOSVersionExpr parses the version field of a PAN-OS stanza.
// It returns the inclusive start (nil: unbounded), the implied exclusive
// upper bound for series forms ("X.Y.*", "X.Y All"; nil: none), and whether
// the expression means all versions.
func parsePANOSVersionExpr(s string) (start, defaultUpper *panosVersion.Version, all bool, err error) {
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
		v, err := parsePANOSVersion(s)
		if err != nil {
			return nil, nil, false, errors.Wrapf(err, "parse version %q", s)
		}
		return &v, nil, false, nil
	}
}

// parsePANOSBoundExpr parses the lessThan / lessThanOrEqual field of a PAN-OS
// stanza into a version bound. isRelease reports whether the bound is a
// concrete release (and thus a fix candidate) rather than a derived series
// boundary.
func parsePANOSBoundExpr(s string, start *panosVersion.Version) (bound *panosVersion.Version, isRelease bool, err error) {
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
		v, err := parsePANOSVersion(s)
		if err != nil {
			return nil, false, errors.Wrapf(err, "parse bound %q", s)
		}
		return &v, true, nil
	}
}

func parseMajorMinor(s string) (major, minor int, err error) {
	ss := strings.Split(s, ".")
	if len(ss) != 2 {
		return 0, 0, errors.Errorf("unexpected version format. expected: %q, actual: %q", "<major>.<minor>", s)
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
