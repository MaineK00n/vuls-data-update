package xml

import (
	"cmp"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	tomcatXML "github.com/MaineK00n/vuls-data-update/pkg/fetch/apache/tomcat/xml"
)

// products maps a page to the CPEs its version numbers belong to. The three
// component pages version independently of the server, and NVD indexes the JK
// connector under two spellings, so each spelling gets its own criterion —
// the db-side part:vendor:product index is built from main CPEs, so a
// criterion is only reachable by a query using the same spelling.
var products = map[string][]ccTypes.CPE{
	"jk":      {"cpe:2.3:a:apache:tomcat_connectors:*:*:*:*:*:*:*:*", "cpe:2.3:a:apache:tomcat_jk_connector:*:*:*:*:*:*:*:*"},
	"native":  {"cpe:2.3:a:apache:tomcat_native:*:*:*:*:*:*:*:*"},
	"taglibs": {"cpe:2.3:a:apache:standard_taglibs:*:*:*:*:*:*:*:*"},
}

const tomcatCPE ccTypes.CPE = "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"

// branchPattern matches the pages named for a Tomcat server branch
// (security-9.xml, security-11.xml), as opposed to a component.
var branchPattern = regexp.MustCompile(`^[0-9]+$`)

// notAVulnerabilityPattern matches the section that collects issues reported
// against Tomcat that are not Tomcat vulnerabilities. Their "Affects:" line
// names downstream distributions rather than Tomcat versions, so no detection
// is emitted for them.
var notAVulnerabilityPattern = regexp.MustCompile(`^Not a vulnerability in`)

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
		dir: filepath.Join(util.CacheDir(), "extract", "apache", "tomcat", "xml"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Apache Tomcat Security Vulnerabilities")
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
		var fetched tomcatXML.Advisory
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		// A CVE is listed once per affected branch, so the same root ID is
		// built from several pages and the parts are merged as they arrive.
		ds, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		for _, data := range ds {
			p := filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID))
			if _, err := os.Stat(p); err == nil {
				f, err := os.Open(p)
				if err != nil {
					return errors.Wrapf(err, "open %s", p)
				}
				defer f.Close()

				var base dataTypes.Data
				if err := json.UnmarshalRead(f, &base); err != nil {
					return errors.Wrapf(err, "decode %s", p)
				}

				data.Merge(base)
			}

			if err := util.Write(p, data, true); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.ApacheTomcatXML,
		Name: new("Apache Tomcat Security Vulnerabilities"),
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

func extract(fetched tomcatXML.Advisory, raws []string) ([]dataTypes.Data, error) {
	// A numbered page is a server branch and carries server versions; a named
	// one is a separately-released component and must be listed above. The
	// fetcher picks up new security-*.xml pages on its own, so an unlisted
	// name is a component whose CPE nobody has chosen yet — the advisory is
	// still extracted, but attributing its versions to the server would be a
	// silent misattribution, so no detection is emitted for it.
	cpes, ok := products[fetched.Branch]
	if !ok {
		if branchPattern.MatchString(fetched.Branch) {
			cpes = []ccTypes.CPE{tomcatCPE}
		} else {
			slog.Warn("no CPE known for Apache Tomcat component page, skipping detections", "branch", fetched.Branch)
		}
	}

	var ds []dataTypes.Data

	// A CVE affecting several branches is listed once per branch, each listing
	// with its own affected range, fix commit and "upgrade to X or later"
	// wording. Merge keeps all of them under the one root ID, so the branch is
	// carried as the segment/condition tag to say which listing each came from.
	tag := segmentTypes.DetectionTag(fetched.Branch)

	for _, s := range fetched.Sections {
		notAVulnerability := notAVulnerabilityPattern.MatchString(s.Name)

		es, _, err := entries(s)
		if err != nil {
			return nil, errors.Wrapf(err, "entries of section %q", s.Name)
		}

		for _, e := range es {
			d := detections(s, e, cpes, notAVulnerability, tag)

			for _, cve := range e.CVEs {
				ds = append(ds, dataTypes.Data{
					ID: dataTypes.RootID(cve),
					Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
						Content: vulnerabilityContentTypes.Content{
							ID:          vulnerabilityContentTypes.VulnerabilityID(cve),
							Title:       e.Title,
							Description: strings.Join(e.Description, "\n"),
							Severity:    severities(e),
							References:  references(cve, e),
						},
						Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: tag}},
					}},
					Detections: d,
					DataSource: sourceTypes.Source{
						ID:   sourceTypes.ApacheTomcatXML,
						Raws: raws,
					},
				})
			}
		}
	}

	return ds, nil
}

// detections turns the entry's "Affects:" line into one CPE criterion per
// version range, per product spelling. The fixed version comes from the
// section title ("Fixed in Apache Tomcat 11.0.24"), which can name more than
// one release when a fix shipped across maintenance lines ("Fixed in Apache
// Tomcat 4.1.13, 4.0.6").
func detections(s tomcatXML.Section, e entry, cpes []ccTypes.CPE, notAVulnerability bool, tag segmentTypes.DetectionTag) []detectionTypes.Detection {
	if notAVulnerability || e.Affects == "" || len(cpes) == 0 {
		return nil
	}

	as, unknown := parseAffects(e.Affects)
	if len(unknown) > 0 {
		slog.Warn("unparseable version range in Affects", "branch", string(tag), "section", s.Name, "cves", e.CVEs, "tokens", unknown)
	}
	if len(as) == 0 {
		return nil
	}

	fixed := fixedVersions(s.Name)

	cns := make([]criterionTypes.Criterion, 0, len(as)*len(cpes))
	for _, cpe := range cpes {
		for _, a := range as {
			cns = append(cns, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					CPE:        cpe,
					Range: &ccRangeTypes.Range{
						Type: ccRangeTypes.RangeTypeVersion,
						// A single version is expressed as a closed range on
						// itself; Range has no equality bound.
						GreaterEqual: cmp.Or(a.GreaterEqual, a.Equal),
						LessEqual:    cmp.Or(a.LessEqual, a.Equal),
					},
					Fixed: fixed,
				},
			})
		}
	}

	return []detectionTypes.Detection{{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Conditions: []conditionTypes.Condition{{
			Criteria: criteriaTypes.Criteria{
				Operator:   criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: cns,
			},
			Tag: tag,
		}},
	}}
}

// sectionVersionPattern pulls the release numbers out of a section title. The
// titles name the server ("Fixed in Apache Tomcat 11.0.24"), a component
// ("Fixed in Apache Tomcat JK Connector 1.2.50", "Fixed in Apache Standard
// Taglib 1.2.3") or nothing at all ("Not fixed in Apache Tomcat 3.x",
// "Unverified"), so a title with no release yields no fixed version.
var sectionVersionPattern = regexp.MustCompile(`[0-9]+(?:\.[0-9A-Za-z]+)*(?:-(?:M|RC)[0-9]+)?`)

func fixedVersions(name string) []string {
	if !strings.HasPrefix(name, "Fixed in ") {
		return nil
	}

	var fixed []string
	for _, v := range sectionVersionPattern.FindAllString(name, -1) {
		// Neither a "3.x" wildcard nor the "5.0.SVN" branch-only placeholder
		// names a release.
		if strings.HasSuffix(v, ".x") || !isRelease(v) {
			continue
		}
		if v = normalize(v); !slices.Contains(fixed, v) {
			fixed = append(fixed, v)
		}
	}
	return fixed
}

func severities(e entry) []severityTypes.Severity {
	if e.Severity == "" {
		return nil
	}
	return []severityTypes.Severity{{
		Type:   severityTypes.SeverityTypeVendor,
		Source: "tomcat.apache.org",
		Vendor: &e.Severity,
	}}
}

func references(cve string, e entry) []referenceTypes.Reference {
	rs := []referenceTypes.Reference{{
		Source: "tomcat.apache.org",
		URL:    fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cve),
	}}

	for _, c := range e.Commits {
		rs = append(rs, referenceTypes.Reference{
			Source: "tomcat.apache.org",
			URL:    fmt.Sprintf("https://github.com/apache/tomcat/commit/%s", c),
		})
	}
	for _, c := range e.ConnectorCommits {
		rs = append(rs, referenceTypes.Reference{
			Source: "tomcat.apache.org",
			URL:    fmt.Sprintf("https://github.com/apache/tomcat-connectors/commit/%s", c),
		})
	}
	for _, r := range e.Revisions {
		rs = append(rs, referenceTypes.Reference{
			Source: "tomcat.apache.org",
			URL:    fmt.Sprintf("https://svn.apache.org/viewvc?view=rev&rev=%s", r),
		})
	}
	for _, b := range e.Bugs {
		rs = append(rs, referenceTypes.Reference{
			Source: "tomcat.apache.org",
			URL:    fmt.Sprintf("https://bz.apache.org/bugzilla/show_bug.cgi?id=%s", b),
		})
	}
	for _, u := range e.References {
		rs = append(rs, referenceTypes.Reference{
			Source: "tomcat.apache.org",
			URL:    u,
		})
	}

	return rs
}
