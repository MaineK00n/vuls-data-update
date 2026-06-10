package nistnvd2

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionType "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
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
	nistnvd2Types "github.com/MaineK00n/vuls-data-update/pkg/fetch/vulncheck/nist-nvd2"
)

// cveIDPattern guards the CVE ID before it is used to build the output
// path. data.ID flows from the (external) VulnCheck NIST NVD2 JSON into
// filepath.Join below; an unvalidated ID such as "CVE-2024/../../x-1"
// would survive util.Split and traverse outside outputDir. Anchoring on
// the full CVE-YYYY-N+ shape keeps both the year directory and the
// filename inside the tree. Serial is \d{4,} (CVE serials can exceed 4
// digits).
var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type options struct {
	dir         string
	concurrency int
}

// Option configures the extraction.
type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

// WithDir sets the output directory.
func WithDir(dir string) Option {
	return dirOption(dir)
}

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

// WithConcurrency sets the number of parallel workers.
func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type extractor struct {
	outputDir string
	r         *utiljson.JSONReader
}

// Extract processes VulnCheck NIST NVD2 data and produces extracted
// detection data.
//
// Unlike extract/nvd/feed/cve/v2, malformed pieces of a CVE entry
// (negated configurations, unparseable CPEs or CVSS vectors, …) are
// logged at WARN and skipped instead of failing the whole extraction,
// following the tolerance of go-cve-dictionary's vulncheck fetcher —
// VulnCheck-enriched data is not under NVD's quality control and a
// single bad entry must not abort the remaining ~350k files.
func Extract(args string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "vulncheck", "nist-nvd2"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract VulnCheck NIST NVD2")

	g, ctx := errgroup.WithContext(context.Background())
	// +1 for the producer goroutine below: counting it inside the
	// limited group with limit==concurrency==1 would deadlock (producer
	// occupies the only slot; no worker can start to drain reqChan).
	// Matches the pattern in extract/nvd/feed/cve/v2.
	g.SetLimit(1 + options.concurrency)

	reqChan := make(chan string)
	g.Go(func() error {
		defer close(reqChan)
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

			select {
			case reqChan <- path:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", args)
		}
		return nil
	})

	for i := 0; i < options.concurrency; i++ {
		g.Go(func() error {
			for path := range reqChan {
				if err := extract(path, args, options.dir); err != nil {
					return errors.Wrapf(err, "extract %s", path)
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return errors.Wrapf(err, "wait for extraction")
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.VulnCheckNISTNVD2,
		Name: new("VulnCheck NIST NVD 2.0"),
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

func extract(cvePath, cveDir, outputDir string) error {
	e := extractor{
		outputDir: outputDir,
		r:         utiljson.NewJSONReader(),
	}

	var fetched nistnvd2Types.CVE
	if err := e.r.Read(cvePath, cveDir, &fetched); err != nil {
		return errors.Wrapf(err, "read json %s", cvePath)
	}

	data, err := e.buildData(fetched)
	if err != nil {
		return errors.Wrapf(err, "buildData %s", cvePath)
	}

	if !cveIDPattern.MatchString(string(data.ID)) {
		return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-\\d{4}-\\d{4,}", data.ID)
	}

	splitted, err := util.Split(string(data.ID), "-", "-")
	if err != nil {
		return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d+", data.ID)
	}

	if err := util.Write(filepath.Join(e.outputDir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(e.outputDir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID)))
	}
	return nil
}

func (e extractor) buildData(fetched nistnvd2Types.CVE) (dataTypes.Data, error) {
	// Detection criteria come from vcConfigurations only — VulnCheck's
	// enriched applicability statements — never from the plain NVD
	// configurations field, mirroring go-cve-dictionary's vulncheck
	// fetcher. vcConfigurations also covers CVEs NVD has not analyzed
	// (vulnStatus Deferred/Rejected), which is the value-add of this
	// data source.
	ds := func() []detectionType.Detection {
		vulnCPEs := parseVulnerableCPEs(fetched.ID, fetched.VCVulnerableCPEs)

		rootCriteria := criteriaTypes.Criteria{
			Operator:  criteriaTypes.CriteriaOperatorTypeOR,
			Criterias: make([]criteriaTypes.Criteria, 0, len(fetched.VCConfigurations)),
		}
		for _, c := range fetched.VCConfigurations {
			ca, ok := configurationToCriteria(fetched.ID, c, vulnCPEs)
			if !ok {
				continue
			}
			rootCriteria.Criterias = append(rootCriteria.Criterias, ca)
		}
		if len(rootCriteria.Criterias) == 0 {
			return nil
		}
		return []detectionType.Detection{{
			Ecosystem: ecosystemTypes.EcosystemTypeCPE,
			Conditions: []conditionTypes.Condition{{
				Criteria: rootCriteria,
			}},
		}}
	}()

	var ss []severityTypes.Severity
	for _, c := range fetched.Metrics.CVSSMetricV2 {
		sv2, err := v2Types.Parse(c.CvssData.VectorString)
		if err != nil {
			slog.Warn("failed to parse cvss v2 vector; skipping", "id", fetched.ID, "vector", c.CvssData.VectorString, "err", err)
			continue
		}
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeCVSSv2,
			Source: c.Source,
			CVSSv2: sv2,
		})
	}
	for _, c := range fetched.Metrics.CVSSMetricV30 {
		v30, err := v30Types.Parse(c.CVSSData.VectorString)
		if err != nil {
			slog.Warn("failed to parse cvss v30 vector; skipping", "id", fetched.ID, "vector", c.CVSSData.VectorString, "err", err)
			continue
		}
		ss = append(ss, severityTypes.Severity{
			Type:    severityTypes.SeverityTypeCVSSv30,
			Source:  c.Source,
			CVSSv30: v30,
		})
	}
	for _, c := range fetched.Metrics.CVSSMetricV31 {
		v31, err := v31Types.Parse(c.CVSSData.VectorString)
		if err != nil {
			slog.Warn("failed to parse cvss v31 vector; skipping", "id", fetched.ID, "vector", c.CVSSData.VectorString, "err", err)
			continue
		}
		ss = append(ss, severityTypes.Severity{
			Type:    severityTypes.SeverityTypeCVSSv31,
			Source:  c.Source,
			CVSSv31: v31,
		})
	}
	for _, c := range fetched.Metrics.CVSSMetricV40 {
		v40, err := v40Types.Parse(c.CVSSData.VectorString)
		if err != nil {
			slog.Warn("failed to parse cvss v40 vector; skipping", "id", fetched.ID, "vector", c.CVSSData.VectorString, "err", err)
			continue
		}
		ss = append(ss, severityTypes.Severity{
			Type:    severityTypes.SeverityTypeCVSSv40,
			Source:  c.Source,
			CVSSv40: v40,
		})
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.ID),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{
			{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(fetched.ID),
					Description: func() string {
						for _, d := range fetched.Descriptions {
							if d.Lang == "en" {
								return d.Value
							}
						}
						return ""
					}(),
					Severity: ss,
					CWE: func() []cweTypes.CWE {
						if len(fetched.Weaknesses) == 0 {
							return nil
						}

						m := make(map[string][]string)
						for _, w := range fetched.Weaknesses {
							for _, d := range w.Description {
								m[w.Source] = append(m[w.Source], d.Value)
							}
						}
						cs := make([]cweTypes.CWE, 0, len(m))
						for s, vs := range m {
							cs = append(cs, cweTypes.CWE{Source: s, CWE: util.Unique(vs)})
						}
						return cs
					}(),
					// References carry NVD's classification tags. Only two
					// of those tags carry detection-relevant signal —
					// "Exploit" and "Mitigation" — so lift those into the
					// existing Exploit / Mitigations slots and drop the rest
					// ("Vendor Advisory", "Patch", "Broken Link", …).
					Mitigations: func() []remediationTypes.Remediation {
						var ms []remediationTypes.Remediation
						for _, r := range fetched.References {
							if slices.Contains(r.Tags, "Mitigation") {
								ms = append(ms, remediationTypes.Remediation{
									Source:      "vulncheck.com",
									Description: r.URL,
								})
							}
						}
						return ms
					}(),
					Exploit: func() []exploitTypes.Exploit {
						var es []exploitTypes.Exploit
						for _, r := range fetched.References {
							if slices.Contains(r.Tags, "Exploit") {
								es = append(es, exploitTypes.Exploit{
									Source: "vulncheck.com",
									Link:   r.URL,
								})
							}
						}
						return es
					}(),
					References: func() []referenceTypes.Reference {
						refs := make([]referenceTypes.Reference, 0, 1+len(fetched.References))
						refs = append(refs, referenceTypes.Reference{
							Source: "vulncheck.com",
							URL:    fmt.Sprintf("https://vulncheck.com/cve/%s", fetched.ID),
						})
						for _, r := range fetched.References {
							refs = append(refs, referenceTypes.Reference{
								Source: r.Source,
								URL:    r.URL,
							})
						}
						return refs
					}(),
					// Freshly added entries carry nanosecond precision while
					// NVD-analyzed ones carry milliseconds; .999999999 accepts
					// any fractional precision including none, matching
					// go-cve-dictionary's vulncheck fetcher.
					Published: utiltime.Parse([]string{"2006-01-02T15:04:05.999999999"}, fetched.Published),
					Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05.999999999"}, fetched.LastModified),
				},
				Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
			},
		},
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.VulnCheckNISTNVD2,
			Raws: e.r.Paths(),
		},
	}, nil
}

// vulnCPE is a pre-parsed entry of vcVulnerableCPEs: the raw CPE 2.3
// formatted string plus the WFN attributes used to associate it with a
// criterion (part:vendor:product) and to read its version.
type vulnCPE struct {
	name string
	wfn  common.WellFormedName
}

// parseVulnerableCPEs parses vcVulnerableCPEs once per CVE. Entries
// that are not valid CPE 2.3 formatted strings are logged at WARN and
// skipped.
func parseVulnerableCPEs(id string, names []string) []vulnCPE {
	cpes := make([]vulnCPE, 0, len(names))
	for _, n := range names {
		wfn, err := naming.UnbindFS(n)
		if err != nil {
			slog.Warn("invalid CPE in vcVulnerableCPEs; skipping", "id", id, "cpe", n, "err", err)
			continue
		}
		cpes = append(cpes, vulnCPE{name: n, wfn: wfn})
	}
	return cpes
}

// configurationToCriteria converts a vcConfigurations entry into a
// criteria tree. Returns ok=false when the configuration carries no
// usable criteria (negated, unexpected operator, or every node
// skipped); the caller drops it, mirroring go-cve-dictionary's
// vulncheck fetcher which skips rather than fails on such entries.
func configurationToCriteria(id string, config nistnvd2Types.Config, vulnCPEs []vulnCPE) (criteriaTypes.Criteria, bool) {
	// negate=true inverts detection semantics, which the criteria tree
	// cannot express. Emitting the children non-negated would invert
	// the meaning, so drop the whole configuration.
	if config.Negate {
		slog.Warn("negate=true on configuration is not supported; skipping", "id", id)
		return criteriaTypes.Criteria{}, false
	}

	ca := criteriaTypes.Criteria{}
	switch config.Operator {
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	case "OR", "":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	default:
		slog.Warn("unexpected configuration operator; skipping", "id", id, "operator", config.Operator)
		return criteriaTypes.Criteria{}, false
	}

	ca.Criterias = make([]criteriaTypes.Criteria, 0, len(config.Nodes))
	for _, n := range config.Nodes {
		child, ok := nodeToCriteria(id, n, vulnCPEs)
		if !ok {
			// An AND configuration with a dropped node would assert a
			// weaker condition than the source data states; refuse the
			// whole configuration rather than emit it partially.
			if ca.Operator == criteriaTypes.CriteriaOperatorTypeAND {
				slog.Warn("node skipped under AND configuration; skipping whole configuration", "id", id)
				return criteriaTypes.Criteria{}, false
			}
			continue
		}
		ca.Criterias = append(ca.Criterias, child)
	}
	if len(ca.Criterias) == 0 {
		return criteriaTypes.Criteria{}, false
	}
	return ca, true
}

// nodeToCriteria converts a configuration node into a criteria subtree.
// Returns ok=false when the node carries no usable criterion.
func nodeToCriteria(id string, n nistnvd2Types.Node, vulnCPEs []vulnCPE) (criteriaTypes.Criteria, bool) {
	if n.Negate {
		slog.Warn("negate=true on node is not supported; skipping", "id", id)
		return criteriaTypes.Criteria{}, false
	}
	ca := criteriaTypes.Criteria{}
	switch n.Operator {
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	// Unlike NVD feed data, VulnCheck leaves the node operator empty for
	// most single-node configurations; treat it as OR like the
	// configuration-level operator.
	case "OR", "":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	default:
		slog.Warn("unexpected node operator; skipping", "id", id, "operator", n.Operator)
		return criteriaTypes.Criteria{}, false
	}

	ca.Criterias = make([]criteriaTypes.Criteria, 0, len(n.CPEMatch))
	for _, match := range n.CPEMatch {
		wfn, err := naming.UnbindFS(match.Criteria)
		if err != nil {
			slog.Warn("invalid CPE in cpeMatch; skipping", "id", id, "cpe", match.Criteria, "err", err)
			continue
		}

		// A range exists when any of the four endpoints is set. This single
		// check decides both whether to emit a Range and whether to expand
		// vcVulnerableCPEs; buildCPEMatches is only meaningful with a range.
		hasRange := match.VersionStartIncluding != "" || match.VersionStartExcluding != "" ||
			match.VersionEndIncluding != "" || match.VersionEndExcluding != ""

		var (
			rangeType  ccRangeTypes.RangeType
			cpeMatches []ccTypes.CPE
		)
		if hasRange {
			cpeMatches, rangeType = buildCPEMatches(match, wfn, vulnCPEs)
		}

		cn := criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: match.Vulnerable,
				FixStatus: func() *fixstatusTypes.FixStatus {
					if match.Vulnerable {
						return &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown}
					}
					return nil
				}(),
				CPE: ccTypes.CPE(match.Criteria),
				Range: func() *ccRangeTypes.Range {
					if !hasRange {
						return nil
					}
					return &ccRangeTypes.Range{
						Type:         rangeType,
						GreaterEqual: match.VersionStartIncluding,
						GreaterThan:  match.VersionStartExcluding,
						LessEqual:    match.VersionEndIncluding,
						LessThan:     match.VersionEndExcluding,
					}
				}(),
				CPEMatches: cpeMatches,
			},
		}

		ca.Criterias = append(ca.Criterias, criteriaTypes.Criteria{
			Operator:   criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: []criterionTypes.Criterion{cn},
		})
	}
	if len(ca.Criterias) == 0 {
		return criteriaTypes.Criteria{}, false
	}
	return ca, true
}

// decideRangeType classifies match's version range: RangeTypeSEMVER when
// every non-empty endpoint parses as semver, RangeTypeUnknown otherwise.
func decideRangeType(match nistnvd2Types.CPEMatch) ccRangeTypes.RangeType {
	for _, v := range []string{match.VersionStartIncluding, match.VersionStartExcluding, match.VersionEndIncluding, match.VersionEndExcluding} {
		switch v {
		case "":
		default:
			if _, err := version.NewSemver(v); err != nil {
				return ccRangeTypes.RangeTypeUnknown
			}
		}
	}
	return ccRangeTypes.RangeTypeSEMVER
}

// buildCPEMatches classifies the CPEMatch's version range and selects the
// vcVulnerableCPEs entries that populate cpecriterion.Criterion.CPEMatches.
// It returns the range type (SEMVER/Unknown) the caller stamps on the
// criterion's Range.
//
// This plays the role extract/nvd/feed/cve/v2's cpematch-feed expansion
// plays for NVD data: vcConfigurations carries no usable matchCriteriaId
// (the field is empty in VulnCheck data), but vcVulnerableCPEs already
// enumerates the concrete vulnerable CPEs per CVE. Entries are associated
// with the criterion by part:vendor:product.
//
// Precondition: invoke only for a match that carries at least one range
// endpoint (nodeToCriteria gates this with hasRange); a no-range match needs
// neither expansion nor range classification.
//
// The criterion's Range still narrows by version on the parent CPE; the
// returned list supplements Range with the versions Range cannot cover:
//
//   - Unknown range: Range cannot be evaluated at detection time, so every
//     concrete entry is added.
//   - SEMVER range: Range already covers every semver-parseable version,
//     so only non-semver entries are added.
//
// Unlike the per-matchCriteriaId cpematch expansion in
// extract/nvd/feed/cve/v2, vcVulnerableCPEs is not scoped to one range: a
// CVE with several ranges over the same product shares one flat list. A
// semver entry outside this criterion's bounds therefore most likely
// belongs to a sibling criterion, not to this one, so for a SEMVER range
// every semver-parseable entry is skipped — in or out of bounds — and only
// the non-semver versions Range cannot evaluate are carried. For an
// Unknown range no per-entry narrowing is possible at all; the full
// product-matched list is carried, trading over-match across sibling
// ranges for not silently losing detection.
func buildCPEMatches(match nistnvd2Types.CPEMatch, wfn common.WellFormedName, vulnCPEs []vulnCPE) ([]ccTypes.CPE, ccRangeTypes.RangeType) {
	rangeType := decideRangeType(match)

	var cpeMatches []ccTypes.CPE
	for _, c := range vulnCPEs {
		if c.wfn.GetString(common.AttributePart) != wfn.GetString(common.AttributePart) ||
			c.wfn.GetString(common.AttributeVendor) != wfn.GetString(common.AttributeVendor) ||
			c.wfn.GetString(common.AttributeProduct) != wfn.GetString(common.AttributeProduct) {
			continue
		}

		// Skip entries whose version is ANY or NA — meta markers, not
		// concrete versions the parent range was meant to enumerate.
		// wfn.GetString returns the logical names "ANY"/"NA" for `*`/`-`, so
		// check the raw value BEFORE unescaping — unescapeWFN strips
		// backslashes blindly, turning a concrete escaped `\*` or `\-` into a
		// bare `*` or `-` indistinguishable from the wildcard markers.
		switch verRaw := c.wfn.GetString(common.AttributeVersion); verRaw {
		case "ANY", "NA":
			continue
		default:
			ver := unescapeWFN(verRaw)

			// SEMVER range: skip every semver-parseable entry — in-bounds
			// versions are already covered by Range, out-of-bounds ones
			// belong to a sibling criterion (see function comment). Only
			// non-semver versions need to appear in CPEMatches.
			if rangeType == ccRangeTypes.RangeTypeSEMVER {
				if _, err := version.NewSemver(ver); err == nil {
					continue
				}
			}
			cpeMatches = append(cpeMatches, ccTypes.CPE(c.name))
		}
	}
	return cpeMatches, rangeType
}

// unescapeWFN removes WFN backslash escaping from attribute values.
// e.g. "7\\.1\\.2" → "7.1.2"
func unescapeWFN(s string) string {
	return strings.ReplaceAll(s, "\\", "")
}
