package v2

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime"
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
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
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
	cpematchTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpematch/v2"
	cveTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
)

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
	cpematchDir   string
	cpematchIndex map[string]string // matchCriteriaId → cpematch file path
	outputDir     string
	r             *utiljson.JSONReader
}

// Extract processes NVD Feed v2 CVE data, expanding cpematch entries
// and producing extracted detection data.
func Extract(cveDir, cpematchDir string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "nvd", "feed", "cve", "v2"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}
	// Clamp non-positive concurrency to 1: the producer goroutine sends
	// into reqChan and needs at least one worker draining it, otherwise
	// g.SetLimit(1+concurrency) either deadlocks (concurrency==0, no
	// worker started) or panics (negative limit).
	if options.concurrency < 1 {
		options.concurrency = 1
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract NVD Feed CVE v2")

	cpematchIndex, err := buildCpematchIndex(cpematchDir)
	if err != nil {
		return errors.Wrap(err, "build cpematch index")
	}

	g, ctx := errgroup.WithContext(context.Background())
	// +1 for the producer goroutine below: counting it inside the
	// limited group with limit==concurrency==1 would deadlock (producer
	// occupies the only slot; no worker can start to drain reqChan).
	// Matches the pattern in extract/microsoft/msuc and extract/debian/tracker/salsa.
	g.SetLimit(1 + options.concurrency)

	reqChan := make(chan string)
	g.Go(func() error {
		defer close(reqChan)
		if err := filepath.WalkDir(cveDir, func(path string, d fs.DirEntry, err error) error {
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
			return errors.Wrapf(err, "walk %s", cveDir)
		}
		return nil
	})

	for i := 0; i < options.concurrency; i++ {
		g.Go(func() error {
			for path := range reqChan {
				if err := extract(path, cveDir, cpematchDir, cpematchIndex, options.dir); err != nil {
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
		ID:   sourceTypes.NVDFeedCVEv2,
		Name: new("NVD Feed CVE v2"),
		Raw: func() []repositoryTypes.Repository {
			var res []repositoryTypes.Repository
			cveGit, _ := utilgit.GetDataSourceRepository(cveDir)
			if cveGit != nil {
				res = append(res, *cveGit)
			}
			cpematchGit, _ := utilgit.GetDataSourceRepository(cpematchDir)
			if cpematchGit != nil {
				res = append(res, *cpematchGit)
			}
			return res
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

func extract(cvePath, cveDir, cpematchDir string, cpematchIndex map[string]string, outputDir string) error {
	e := extractor{
		cpematchDir:   cpematchDir,
		cpematchIndex: cpematchIndex,
		outputDir:     outputDir,
		r:             utiljson.NewJSONReader(),
	}

	var fetched cveTypes.CVE
	if err := e.r.Read(cvePath, cveDir, &fetched); err != nil {
		return errors.Wrapf(err, "read json %s", cvePath)
	}

	data, err := e.buildData(fetched)
	if err != nil {
		return errors.Wrapf(err, "buildData %s", cvePath)
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

func (e extractor) buildData(fetched cveTypes.CVE) (dataTypes.Data, error) {
	ds, err := func() ([]detectionType.Detection, error) {
		switch len(fetched.Configurations) {
		case 0:
			return nil, nil
		default:
			rootCriteria := criteriaTypes.Criteria{
				Operator:  criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: make([]criteriaTypes.Criteria, 0, len(fetched.Configurations)),
			}
			for _, c := range fetched.Configurations {
				ca, err := e.configurationToCriteria(c)
				if err != nil {
					return nil, errors.Wrapf(err, "configuration to criteria. ID: %s", fetched.ID)
				}
				rootCriteria.Criterias = append(rootCriteria.Criterias, ca)
			}
			return []detectionType.Detection{{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Conditions: []conditionTypes.Condition{{
					Criteria: rootCriteria,
				}},
			}}, nil
		}
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "build detection. ID: %s", fetched.ID)
	}

	ss := make([]severityTypes.Severity, 0, len(fetched.Metrics.CVSSMetricV2)+len(fetched.Metrics.CVSSMetricV30)+len(fetched.Metrics.CVSSMetricV31)+len(fetched.Metrics.CVSSMetricV40))
	switch cap(ss) {
	case 0:
		ss = nil
	default:
		for _, c := range fetched.Metrics.CVSSMetricV2 {
			sv2, err := v2Types.Parse(c.CvssData.VectorString)
			if err != nil {
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v2 parse. vector: %s", c.CvssData.VectorString)
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
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v30 parse. vector: %s", c.CVSSData.VectorString)
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
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v31 parse. vector: %s", c.CVSSData.VectorString)
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
				return dataTypes.Data{}, errors.Wrapf(err, "cvss v40 parse. vector: %s", c.CVSSData.VectorString)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv40,
				Source:  c.Source,
				CVSSv40: v40,
			})
		}
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
					References: func() []referenceTypes.Reference {
						refs := make([]referenceTypes.Reference, 0, 1+len(fetched.References))
						refs = append(refs, referenceTypes.Reference{
							Source: "nvd.nist.gov",
							URL:    fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", fetched.ID),
						})
						for _, r := range fetched.References {
							// TODO: propagate r.Tags ("Patch",
							// "Vendor Advisory", "Exploit",
							// "Mitigation", "Broken Link", …) once
							// types/data/reference.Reference grows a
							// Tags []string field. Downstream consumers
							// (vuls0 Exploit/Mitigation derivation) rely
							// on these tags; the omission here matches
							// the api/cve sibling and is intentional
							// only because the schema does not yet
							// carry the field.
							refs = append(refs, referenceTypes.Reference{
								Source: r.Source,
								URL:    r.URL,
							})
						}
						return refs
					}(),
					Published: utiltime.Parse([]string{"2006-01-02T15:04:05.000"}, fetched.Published),
					Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05.000"}, fetched.LastModified),
				},
				Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
			},
		},
		Detections: ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.NVDFeedCVEv2,
			Raws: e.r.Paths(),
		},
	}, nil
}

func (e extractor) configurationToCriteria(config cveTypes.Config) (criteriaTypes.Criteria, error) {
	if config.Negate {
		return criteriaTypes.Criteria{}, errors.Errorf("Configuration.Negate=true is not implemented")
	}

	ca := criteriaTypes.Criteria{}
	switch config.Operator {
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	case "OR", "":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	default:
		return criteriaTypes.Criteria{}, errors.Errorf("unexpected configuration operator. expected: %q, actual: %q", []string{"AND", "OR", ""}, config.Operator)
	}

	ca.Criterias = make([]criteriaTypes.Criteria, 0, len(config.Nodes))
	for _, n := range config.Nodes {
		child, err := e.nodeToCriteria(n)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrap(err, "nodeToCriteria")
		}
		ca.Criterias = append(ca.Criterias, child)
	}
	return ca, nil
}

func (e extractor) nodeToCriteria(n cveTypes.Node) (criteriaTypes.Criteria, error) {
	if n.Negate {
		return criteriaTypes.Criteria{}, errors.Errorf("Node.Negate=true is not implemented")
	}
	ca := criteriaTypes.Criteria{}
	switch n.Operator {
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	case "OR":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	default:
		return criteriaTypes.Criteria{}, errors.Errorf("unexpected node operator. expected: %q, actual: %q", []string{"AND", "OR"}, n.Operator)
	}

	ca.Criterias = make([]criteriaTypes.Criteria, 0, len(n.CPEMatch))
	for _, match := range n.CPEMatch {
		if _, err := naming.UnbindFS(match.Criteria); err != nil {
			return criteriaTypes.Criteria{}, errors.Wrapf(err, "invalid format. CPE: %s", match.Criteria)
		}

		hasRange := match.VersionStartIncluding != "" || match.VersionStartExcluding != "" ||
			match.VersionEndIncluding != "" || match.VersionEndExcluding != ""

		rangeType := decideRangeType(match)

		// A ranged match keeps its range narrowing on the parent CPE and,
		// in addition, expands the cpematch feed into CPEMatches entries:
		//   - Unknown range: the range cannot be evaluated at detection
		//     time, so every expanded version is added.
		//   - SEMVER range: the range already covers every semver-parseable
		//     version inside it; only versions Range cannot cover
		//     (non-semver, or the rare semver version outside the range)
		//     need to appear in CPEMatches.
		var cpeMatches []ccTypes.CPE
		if hasRange {
			var err error
			cpeMatches, err = e.buildCPEMatches(match, rangeType)
			if err != nil {
				return criteriaTypes.Criteria{}, err
			}
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
	return ca, nil
}

// semverBounds is the pre-parsed form of a CPEMatch's four range
// endpoints. Caller parses once per match and reuses across every
// cpematch entry expanded from that match.
type semverBounds struct {
	ge *version.Version // versionStartIncluding (>=)
	gt *version.Version // versionStartExcluding (>)
	le *version.Version // versionEndIncluding   (<=)
	lt *version.Version // versionEndExcluding   (<)
}

// parseSemverBounds parses the four range endpoints in match. Returns
// ok=false if any non-empty endpoint fails to parse — caller falls back
// to treating every cpematch entry as out-of-range.
func parseSemverBounds(match cveTypes.CPEMatch) (semverBounds, bool) {
	parse := func(s string) (*version.Version, bool) {
		if s == "" {
			return nil, true
		}
		v, err := version.NewSemver(s)
		return v, err == nil
	}
	var (
		b  semverBounds
		ok bool
	)
	if b.ge, ok = parse(match.VersionStartIncluding); !ok {
		return semverBounds{}, false
	}
	if b.gt, ok = parse(match.VersionStartExcluding); !ok {
		return semverBounds{}, false
	}
	if b.le, ok = parse(match.VersionEndIncluding); !ok {
		return semverBounds{}, false
	}
	if b.lt, ok = parse(match.VersionEndExcluding); !ok {
		return semverBounds{}, false
	}
	return b, true
}

// versionInBounds reports whether v satisfies the pre-parsed range.
func versionInBounds(v *version.Version, b semverBounds) bool {
	if b.ge != nil && v.LessThan(b.ge) {
		return false
	}
	if b.gt != nil && !v.GreaterThan(b.gt) {
		return false
	}
	if b.le != nil && v.GreaterThan(b.le) {
		return false
	}
	if b.lt != nil && !v.LessThan(b.lt) {
		return false
	}
	return true
}

// buildCpematchIndex walks the cpematch feed directory and maps each
// matchCriteriaId (the JSON file's basename) to its file path. The raw
// cpematch fetch layout stores files in FNV-hashed subdirectories keyed
// by vendor:product, but the CVE feed and the cpematch feed disagree on
// some product spellings (e.g. nx-os vs nx_os), so that hash is not
// reproducible from the CVE side. Indexing by matchCriteriaId sidesteps
// the problem entirely.
func buildCpematchIndex(cpematchDir string) (map[string]string, error) {
	index := make(map[string]string)
	if err := filepath.WalkDir(cpematchDir, func(path string, d fs.DirEntry, err error) error {
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
		index[strings.TrimSuffix(d.Name(), ".json")] = path
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", cpematchDir)
	}
	return index, nil
}

// cpeNamesFromCpematch loads the cpematch file for the given matchCriteriaId
// via the prebuilt index and returns its expanded CPE names.
func (e extractor) cpeNamesFromCpematch(matchCriteriaId string) ([]string, error) {
	path, ok := e.cpematchIndex[matchCriteriaId]
	if !ok {
		return nil, errors.Errorf("cpematch not found for matchCriteriaId=%s", matchCriteriaId)
	}

	var cpeMatch cpematchTypes.MatchCriteria
	if err := e.r.Read(path, e.cpematchDir, &cpeMatch); err != nil {
		return nil, errors.Wrapf(err, "read json %s", path)
	}

	ns := make([]string, 0, len(cpeMatch.Matches))
	for _, m := range cpeMatch.Matches {
		ns = append(ns, m.CPEName)
	}
	return ns, nil
}

// buildCPEMatches expands the cpematch feed entries for one ranged CPEMatch
// into the list that should populate cpecriterion.Criterion.CPEMatches.
// Caller is responsible for only invoking this when match has a non-empty
// range (caller-side hasRange check); calling on a no-range match is wasted
// work but otherwise harmless.
//
// Lookup failures happen when the CVE feed and the cpematch feed have not
// been snapshotted atomically: a freshly added matchCriteriaId can exist in
// the CVE snapshot while the cpematch snapshot is still slightly behind.
// Severity depends on rangeType:
//
//   - SEMVER: returns (nil, nil) after a WARN. The Range still evaluates
//     against semver-parseable versions, so detection only loses the
//     non-semver versions the cpematch would have enumerated; emitting the
//     criterion with Range alone is acceptable.
//   - Unknown: returns (nil, wrapped err). The Range cannot be evaluated at
//     detection time (compare errors are swallowed) and there is no
//     CPEMatches fallback, so this CVE+match would be silently
//     undetectable. Refuse to emit a broken criterion — caller fails the
//     extract and the operator refreshes the cpematch snapshot.
func (e extractor) buildCPEMatches(match cveTypes.CPEMatch, rangeType ccRangeTypes.RangeType) ([]ccTypes.CPE, error) {
	ns, err := e.cpeNamesFromCpematch(match.MatchCriteriaID)
	if err != nil {
		if rangeType == ccRangeTypes.RangeTypeUnknown {
			return nil, errors.Wrapf(err, "cpematch lookup failed for unknown range; matchCriteriaID=%s criteria=%s", match.MatchCriteriaID, match.Criteria)
		}
		slog.Warn("cpematch lookup failed", "matchCriteriaID", match.MatchCriteriaID, "criteria", match.Criteria, "err", err)
		return nil, nil
	}

	// Pre-parse range bounds once per match instead of re-parsing them
	// inside the per-entry coverage check. boundsOK=false only when a
	// SEMVER endpoint somehow fails to parse here despite decideRangeType
	// having already validated it; in that case we fall back to emitting
	// every concrete entry.
	var (
		bounds   semverBounds
		boundsOK bool
	)
	if rangeType == ccRangeTypes.RangeTypeSEMVER {
		bounds, boundsOK = parseSemverBounds(match)
	}

	cpeMatches := make([]ccTypes.CPE, 0, len(ns))
	for _, n := range ns {
		wfn, err := naming.UnbindFS(n)
		if err != nil {
			// Surface invalid CPE entries rather than silently dropping
			// them — without this it is hard to explain a missing
			// CPEMatches entry downstream. Logged at WARN with the parent
			// matchCriteriaId so the upstream data issue can be located.
			slog.Warn("invalid CPE in cpematch expansion; skipping", "matchCriteriaID", match.MatchCriteriaID, "cpeName", n, "err", err)
			continue
		}
		// Skip cpematch entries whose version is ANY or NA — meta markers,
		// not concrete versions the parent range was meant to enumerate.
		// Without this skip we would inject NA-version entries for every
		// ranged match whose cpematch happens to include `-`, producing
		// spurious vendor:product-only hits at detection time for any
		// scanned CPE that shares the vendor and product. wfn.GetString
		// returns the logical names "ANY"/"NA" for `*`/`-`, so check the
		// raw value BEFORE unescaping — unescapeWFN strips backslashes
		// blindly, turning a concrete escaped `\*` or `\-` into a bare `*`
		// or `-` that would be indistinguishable from the wildcard markers.
		verRaw := wfn.GetString(common.AttributeVersion)
		switch verRaw {
		case "ANY", "NA":
			continue
		}
		ver := unescapeWFN(verRaw)

		// SEMVER range: skip if the entry's version is semver-parseable and
		// falls inside the range — the Range already covers it. Non-semver
		// or out-of-range entries need to appear in CPEMatches (the latter
		// accounts for a tiny fraction of cases — segment-count or
		// pre-release ordering quirks in NVD data).
		if boundsOK {
			if sv, err := version.NewSemver(ver); err == nil && versionInBounds(sv, bounds) {
				continue
			}
		}
		cpeMatches = append(cpeMatches, ccTypes.CPE(n))
	}
	return cpeMatches, nil
}

// decideRangeType checks whether every non-empty range endpoint parses as
// semver and returns the cpecriterion.RangeType the criterion should carry.
// Non-semver endpoints downgrade the whole match to Unknown (detection
// cannot evaluate Range; CPEMatches must cover every concrete version).
func decideRangeType(match cveTypes.CPEMatch) ccRangeTypes.RangeType {
	for _, v := range []string{match.VersionStartIncluding, match.VersionStartExcluding, match.VersionEndIncluding, match.VersionEndExcluding} {
		if v == "" {
			continue
		}
		if _, err := version.NewSemver(v); err != nil {
			return ccRangeTypes.RangeTypeUnknown
		}
	}
	return ccRangeTypes.RangeTypeSEMVER
}

// unescapeWFN removes WFN backslash escaping from attribute values.
// e.g. "7\\.1\\.2" → "7.1.2"
func unescapeWFN(s string) string {
	return strings.ReplaceAll(s, "\\", "")
}
