package nistnvd2

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

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
// A malformed piece of a CVE entry (negate=true, an unexpected
// configuration/node operator, an invalid CPE in cpeMatch or
// vcVulnerableCPEs, an unparseable CVSS vector) is a hard error rather
// than a silent skip, so unexpected data surfaces instead of being
// dropped — silently skipping a cpeMatch would also weaken an AND
// configuration into an over-broad detection. The one tolerated quirk is
// an empty node operator, which is mapped to OR.
func Extract(args string, opts ...Option) error {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "extract", "vulncheck", "nist-nvd2"),
		concurrency: runtime.NumCPU(),
	}

	for _, o := range opts {
		o.apply(options)
	}

	// A non-positive concurrency would start no workers while the
	// producer blocks on reqChan forever; clamp to at least one worker.
	options.concurrency = max(1, options.concurrency)

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract VulnCheck NIST NVD2")

	g, ctx := errgroup.WithContext(context.Background())
	// +1 for the producer goroutine below: counting it inside the
	// limited group with limit==concurrency==1 would deadlock (producer
	// occupies the only slot; no worker can start to drain reqChan).
	g.SetLimit(1 + options.concurrency)

	reqChan := make(chan string)
	g.Go(func() error {
		defer close(reqChan)
		if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return errors.Wrapf(err, "walk dir entry %s", path)
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

	// Validate the CVE ID's year segment via util.Split + time.Parse, the
	// same shape the sibling extractors (nuclei, jvn, …) use. This is
	// deliberately kept consistent with those siblings and does NOT harden
	// the output filename against a malformed serial carrying path
	// separators — no sibling does, so that defense, if wanted, belongs in a
	// repo-wide change across all fetch/extract rather than only here.
	splitted, err := util.Split(string(data.ID), "-", "-")
	if err != nil {
		return errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", data.ID)
	}
	if _, err := time.Parse("2006", splitted[1]); err != nil {
		return errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", data.ID)
	}

	if err := util.Write(filepath.Join(e.outputDir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(e.outputDir, "data", splitted[1], fmt.Sprintf("%s.json", data.ID)))
	}
	return nil
}

func (e extractor) buildData(fetched nistnvd2Types.CVE) (dataTypes.Data, error) {
	// The detection is a single CPE condition (not several — Condition.Tag is
	// for segmenting detections by product/stream, which is not what this split
	// is; nvd/feed/cve/v2 likewise emits one condition). Its root criteria always
	// ORs the present groups, one per raw input field, in a uniform shape — the
	// structure never varies with the data (no single-group collapse), so it
	// reads the same for every record:
	//
	//   group 1 — vcConfigurations: a root OR over configurations, each an
	//   AND/OR over its nodes, each node combining its cpeMatch criteria.
	//   group 2 — vcVulnerableCPEs: a flat OR of concrete CPEs, carrying ONLY
	//   the entries group 1 does not already detect (following NVD) — versions a
	//   Range cannot express (non-semver) or does not cover, and products the
	//   configurations omit.
	//
	// Both are built from VulnCheck's enriched fields only — never the plain NVD
	// configurations.
	ds, err := func() ([]detectionType.Detection, error) {
		// A Rejected CVE is withdrawn, so it must not produce detections —
		// VulnCheck keeps vcConfigurations on some rejected entries, and
		// emitting them would flag a withdrawn CVE (a false positive). The
		// vulnerability content (the rejection reason) is still emitted, as
		// other extractors (nvd/feed/cve/v2, mitre/v5) keep rejected records.
		if fetched.VulnStatus == "Rejected" {
			return nil, nil
		}

		// Accumulate the present groups directly into the root OR criteria.
		criteria := criteriaTypes.Criteria{Operator: criteriaTypes.CriteriaOperatorTypeOR}

		// Group 1: vcConfigurations applicability tree (CPE + version Range).
		cc, err := vcConfigurationsCriteria(fetched.VCConfigurations)
		if err != nil {
			return nil, errors.Wrap(err, "vcConfigurations criteria")
		}
		if len(cc.Criterias) > 0 {
			criteria.Criterias = append(criteria.Criterias, cc)
		}

		// What group 1 already detects, per product — used to drop the
		// redundant vcVulnerableCPEs from group 2.
		coverage, err := buildConfigCoverage(fetched.VCConfigurations)
		if err != nil {
			return nil, errors.Wrap(err, "build config coverage")
		}

		// Group 2: vcVulnerableCPEs not already covered by group 1.
		vulnCPEs, err := parseVulnerableCPEs(fetched.VCVulnerableCPEs)
		if err != nil {
			return nil, errors.Wrap(err, "parse vcVulnerableCPEs")
		}
		vc, err := vulnerableCPECriteria(vulnCPEs, coverage)
		if err != nil {
			return nil, errors.Wrap(err, "vulnerable cpe criteria")
		}
		if len(vc.Criterions) > 0 {
			criteria.Criterias = append(criteria.Criterias, vc)
		}

		if len(criteria.Criterias) == 0 {
			return nil, nil
		}
		return []detectionType.Detection{{
			Ecosystem:  ecosystemTypes.EcosystemTypeCPE,
			Conditions: []conditionTypes.Condition{{Criteria: criteria}},
		}}, nil
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
									Source:      r.Source,
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
									Source: r.Source,
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
					// Timestamps carry either millisecond or nanosecond
					// precision depending on the entry; .999999999 accepts any
					// fractional precision including none.
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

// parseVulnerableCPEs parses vcVulnerableCPEs once per CVE. An entry
// that is not a valid CPE 2.3 formatted string is an error: it does not
// occur in the current feed, so encountering one signals unexpected data.
func parseVulnerableCPEs(names []string) ([]vulnCPE, error) {
	cpes := make([]vulnCPE, 0, len(names))
	for _, n := range names {
		wfn, err := naming.UnbindFS(n)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid format. CPE: %s", n)
		}
		cpes = append(cpes, vulnCPE{name: n, wfn: wfn})
	}
	return cpes, nil
}

// pvpKey returns the part:vendor:product key used to group vcVulnerableCPEs by
// product.
func pvpKey(wfn common.WellFormedName) string {
	return fmt.Sprintf("%s:%s:%s", wfn.GetString(common.AttributePart), wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))
}

// vulnerableCPECriteria builds the vcVulnerableCPEs condition: the concrete
// vulnerable CPEs that the vcConfigurations condition does NOT already detect
// (coverage), grouped one criterion per part:vendor:product. Each criterion is
// a product-wildcard primary CPE (part:vendor:product fixed, every other
// attribute ANY) with the product's concrete CPEs in cpe_matches. A scanned CPE
// with a concrete version hits an exact cpe_matches entry; a version-less scan
// falls to the vuls2 vendor:product confidence tier — both faithful to the
// source, since the concrete attributes live in cpe_matches. The result is flat
// (criterions directly under one OR); output order is normalized by Sort().
//
// An entry is dropped when:
//   - its version is ANY or NA — ANY is a superset of every concrete version
//     (it would turn a versioned criterion into a vendor:product-only hit) and
//     NA is disjoint from every concrete version (dead weight). naming.UnbindFS
//     maps the "*"/"-" markers to the logical values, so GetString returns
//     "ANY"/"NA" for them, whereas a concrete version — including an escaped
//     literal "\*"/"\-" — comes back as its bound string; the equality check
//     therefore drops only the true markers.
//   - the vcConfigurations condition already detects it (coverage.covers):
//     a whole-product criterion, or a semver Range that includes the version.
//     Following NVD, the concrete list only supplements what ranges cannot.
func vulnerableCPECriteria(vulnCPEs []vulnCPE, coverage map[string]productCoverage) (criteriaTypes.Criteria, error) {
	root := criteriaTypes.Criteria{Operator: criteriaTypes.CriteriaOperatorTypeOR}
	for key, group := range indexByProduct(vulnCPEs) {
		cov := coverage[key] // zero value if absent → covers nothing
		matches := make([]ccTypes.CPE, 0, len(group))
		for _, c := range group {
			verRaw := c.wfn.GetString(common.AttributeVersion)
			switch verRaw {
			case "ANY", "NA":
				continue
			}
			if cov.covers(verRaw) {
				continue
			}
			matches = append(matches, ccTypes.CPE(c.name))
		}
		if len(matches) == 0 {
			continue
		}
		p := common.NewWellFormedName()
		for _, a := range []string{common.AttributePart, common.AttributeVendor, common.AttributeProduct} {
			if err := p.Set(a, group[0].wfn.Get(a)); err != nil {
				return criteriaTypes.Criteria{}, errors.Wrapf(err, "set %s on product-wildcard cpe. cpe: %s", a, group[0].name)
			}
		}
		root.Criterions = append(root.Criterions, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
				CPE:        ccTypes.CPE(naming.BindToFS(p)),
				CPEMatches: matches,
			},
		})
	}
	return root, nil
}

// indexByProduct groups parsed vcVulnerableCPEs by part:vendor:product.
func indexByProduct(vulnCPEs []vulnCPE) map[string][]vulnCPE {
	idx := make(map[string][]vulnCPE)
	for _, c := range vulnCPEs {
		k := pvpKey(c.wfn)
		idx[k] = append(idx[k], c)
	}
	return idx
}

// productCoverage summarizes, per part:vendor:product, what the
// vcConfigurations group already detects: whole is true when a whole-product
// criterion (version NA, or ANY with no range) matches every version; ranges
// are its semver version ranges (including a concrete exact version as a point
// range).
type productCoverage struct {
	whole  bool
	ranges []semverRange
}

// covers reports whether a vcVulnerableCPE version is already detected by the
// vcConfigurations group. The zero value (product absent from every
// configuration) covers nothing.
func (c productCoverage) covers(verRaw string) bool {
	if c.whole {
		return true
	}
	v, err := version.NewSemver(unescapeVersion(verRaw))
	if err != nil {
		return false // non-semver: a Range cannot decide it → keep as supplement
	}
	for _, r := range c.ranges {
		if r.covers(v) {
			return true
		}
	}
	return false
}

// semverRange is a parsed vcConfigurations version range.
type semverRange struct {
	ge, gt, le, lt *version.Version
}

func (r semverRange) covers(v *version.Version) bool {
	if r.ge != nil && v.LessThan(r.ge) {
		return false
	}
	if r.gt != nil && !v.GreaterThan(r.gt) {
		return false
	}
	if r.le != nil && v.GreaterThan(r.le) {
		return false
	}
	if r.lt != nil && !v.LessThan(r.lt) {
		return false
	}
	return true
}

// buildConfigCoverage indexes the vulnerable=true vcConfigurations cpeMatch
// criteria by part:vendor:product so vulnerableCPECriteria can drop the
// vcVulnerableCPEs the configuration already detects as vulnerable. Only
// semver-evaluable ranges contribute (an unknown range cannot decide membership,
// so its product's enumerations are kept). The cpeMatch CPEs were already
// validated by configurationToCriteria.
func buildConfigCoverage(configs []nistnvd2Types.Config) (map[string]productCoverage, error) {
	cov := make(map[string]productCoverage)
	for _, conf := range configs {
		for _, n := range conf.Nodes {
			for _, m := range n.CPEMatch {
				// Coverage means "already detected as vulnerable by group 1", so
				// only vulnerable=true matches contribute. A vulnerable=false
				// clause (e.g. an NVD running-on platform) detects nothing;
				// counting it would let it suppress a colliding vcVulnerableCPEs
				// entry, dropping a vulnerable CPE from both groups.
				if !m.Vulnerable {
					continue
				}
				wfn, err := naming.UnbindFS(m.Criteria)
				if err != nil {
					return nil, errors.Wrapf(err, "invalid format. CPE: %s", m.Criteria)
				}
				key := pvpKey(wfn)
				c := cov[key] // zero value if absent
				hasRange := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
					m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
				switch ver := wfn.GetString(common.AttributeVersion); {
				case ver == "NA", ver == "ANY" && !hasRange:
					c.whole = true // matches every version
				case hasRange:
					if decideRangeType(m) == ccRangeTypes.RangeTypeSEMVER {
						c.ranges = append(c.ranges, semverRange{
							ge: semverOrNil(m.VersionStartIncluding),
							gt: semverOrNil(m.VersionStartExcluding),
							le: semverOrNil(m.VersionEndIncluding),
							lt: semverOrNil(m.VersionEndExcluding),
						})
					}
				default: // concrete exact version (no range): covers just that version
					if v := semverOrNil(unescapeVersion(ver)); v != nil {
						c.ranges = append(c.ranges, semverRange{ge: v, le: v})
					}
				}
				cov[key] = c
			}
		}
	}
	return cov, nil
}

// semverOrNil parses s as semver, returning nil on empty or non-semver input.
// Range endpoints from the raw JSON are not WFN-escaped, so no unescape here.
func semverOrNil(s string) *version.Version {
	if s == "" {
		return nil
	}
	v, err := version.NewSemver(s)
	if err != nil {
		return nil
	}
	return v
}

// unescapeVersion strips WFN backslash escaping from a version attribute value
// ("6\.3\.0" → "6.3.0") so it can be parsed as semver.
func unescapeVersion(s string) string {
	return strings.ReplaceAll(s, "\\", "")
}

// vcConfigurationsCriteria builds the criteria tree for vcConfigurations,
// mirroring the sibling nvd/feed/cve/v2 extractor: a root OR over each
// configuration, each configuration an AND/OR over its nodes, each node an
// AND/OR over its cpeMatch criteria. The applicability structure is preserved
// as-is (no flattening or collapsing) so it stays parallel to the NVD v2 output;
// the concrete vulnerable CPEs live in the separate vcVulnerableCPEs condition,
// not here.
func vcConfigurationsCriteria(configs []nistnvd2Types.Config) (criteriaTypes.Criteria, error) {
	root := criteriaTypes.Criteria{
		Operator:  criteriaTypes.CriteriaOperatorTypeOR,
		Criterias: make([]criteriaTypes.Criteria, 0, len(configs)),
	}
	for _, config := range configs {
		ca, err := configurationToCriteria(config)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrap(err, "configuration to criteria")
		}
		root.Criterias = append(root.Criterias, ca)
	}
	return root, nil
}

// configurationToCriteria converts one vcConfigurations entry into a criteria
// subtree (AND/OR over its nodes). negate=true and an unexpected operator are
// errors rather than silent skips, so unexpected data surfaces instead of being
// dropped (neither occurs in the feed). Mirrors nvd/feed/cve/v2.
func configurationToCriteria(config nistnvd2Types.Config) (criteriaTypes.Criteria, error) {
	if config.Negate {
		return criteriaTypes.Criteria{}, errors.New("negate=true on configuration is not supported")
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
		child, err := nodeToCriteria(n)
		if err != nil {
			return criteriaTypes.Criteria{}, errors.Wrap(err, "node to criteria")
		}
		ca.Criterias = append(ca.Criterias, child)
	}
	return ca, nil
}

// nodeToCriteria converts one configuration node into a criteria subtree whose
// operator (AND/OR) combines the node's cpeMatch criteria. Malformed shapes are
// errors, as in configurationToCriteria.
func nodeToCriteria(n nistnvd2Types.Node) (criteriaTypes.Criteria, error) {
	if n.Negate {
		return criteriaTypes.Criteria{}, errors.New("negate=true on node is not supported")
	}

	ca := criteriaTypes.Criteria{}
	switch n.Operator {
	case "AND":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeAND
	// vcConfigurations leaves the node operator empty for most single-CPE nodes
	// (NVD v2's plain configurations always set it); treat "" as OR.
	case "OR", "":
		ca.Operator = criteriaTypes.CriteriaOperatorTypeOR
	default:
		return criteriaTypes.Criteria{}, errors.Errorf("unexpected node operator. expected: %q, actual: %q", []string{"AND", "OR", ""}, n.Operator)
	}

	// Each cpeMatch is a criterion placed directly under the node; the node's
	// operator combines them. NVD v2 wraps each cpeMatch in its own
	// single-criterion OR sub-criteria, which is semantically identical
	// (Criteria.Operator applies to Criterions and Criterias alike) but the flat
	// form mirrors the source's flat cpeMatch array without the empty wrapper.
	ca.Criterions = make([]criterionTypes.Criterion, 0, len(n.CPEMatch))
	for _, match := range n.CPEMatch {
		if _, err := naming.UnbindFS(match.Criteria); err != nil {
			return criteriaTypes.Criteria{}, errors.Wrapf(err, "invalid format. CPE: %s", match.Criteria)
		}

		// A range exists when any of the four endpoints is set.
		hasRange := match.VersionStartIncluding != "" || match.VersionStartExcluding != "" ||
			match.VersionEndIncluding != "" || match.VersionEndExcluding != ""

		ca.Criterions = append(ca.Criterions, criterionTypes.Criterion{
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
						Type:         decideRangeType(match),
						GreaterEqual: match.VersionStartIncluding,
						GreaterThan:  match.VersionStartExcluding,
						LessEqual:    match.VersionEndIncluding,
						LessThan:     match.VersionEndExcluding,
					}
				}(),
			},
		})
	}
	return ca, nil
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
