package osv

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	sourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/rocky/osv"
)

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

func Extract(inputDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "rocky", "osv"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Rocky Linux OSV")
	entries, err := os.ReadDir(inputDir)
	if err != nil {
		return errors.Wrapf(err, "read dir %s", inputDir)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == ".git" {
			continue
		}

		if err := filepath.WalkDir(filepath.Join(inputDir, entry.Name()), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			r := utiljson.NewJSONReader()
			var fetched osv.OSV
			if err := r.Read(path, inputDir, &fetched); err != nil {
				return errors.Wrapf(err, "read json %s", path)
			}

			if entry.Name() != "RLSA" && len(fetched.Affected) == 0 {
				return nil
			}

			extracted, err := extract(fetched, r.Paths())
			if err != nil {
				return errors.Wrapf(err, "extract %s", fetched.ID)
			}

			splitted, err := util.Split(string(extracted.ID), "-", ":")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", fmt.Sprintf("%s-yyyy:\\d{4,}", entry.Name()), extracted.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", fmt.Sprintf("%s-yyyy:\\d{4,}", entry.Name()), extracted.ID)
			}

			if err := util.Write(filepath.Join(options.dir, "data", entry.Name(), splitted[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", entry.Name(), splitted[1], fmt.Sprintf("%s.json", extracted.ID)))
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", inputDir)
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.RockyOSV,
		Name: func() *string { t := "Rocky Linux OSV"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(inputDir)
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

func extract(fetched osv.OSV, raws []string) (dataTypes.Data, error) {
	if fetched.Withdrawn != "" {
		return dataTypes.Data{}, errors.Errorf("unexpected withdrawn. expected: nil, actual: %+v", fetched.Withdrawn)
	}
	if fetched.Aliases != nil {
		return dataTypes.Data{}, errors.Errorf("unexpected aliases. expected: nil, actual: %+v", fetched.Aliases)
	}

	cs := make(map[int][]criterionTypes.Criterion) // major -> []Criterion

	for _, a := range fetched.Affected {
		if len(a.Versions) != 0 {
			return dataTypes.Data{}, errors.Errorf("unexpected versions count in affected. expected: %d, actual: %d", 0, len(a.Versions))
		}
		if a.EcosystemSpecific != nil {
			return dataTypes.Data{}, errors.Errorf("unexpected ecosystem_specific in affected. expected: %v, actual: %+v", nil, a.EcosystemSpecific)
		}
		// At this time, limit the ranges to just single element.
		// If there appear OSVs with multiple ranges, it should have additional information to distinguish them. We will investigate it at that time, errors that occur here will trigger us.
		if len(a.Ranges) != 1 {
			return dataTypes.Data{}, errors.Errorf("unexpected ranges count. expected: %d, actual: %d", 1, len(a.Ranges))
		}
		if len(a.Severity) != 0 {
			return dataTypes.Data{}, errors.Errorf("unexpected severity count in affected. expected: %d, actual: %d", 0, len(a.Severity))
		}

		lhs, rhs, ok := strings.Cut(a.Package.Ecosystem, ":")
		if !ok {
			return dataTypes.Data{}, errors.Errorf("unexpected ecosystem format. expected: %q, actual: %q", "Rocky Linux:<major>", a.Package.Ecosystem)
		}
		if lhs != "Rocky Linux" {
			return dataTypes.Data{}, errors.Errorf("unexpected ecosystem. expected: %q, actual: %q", "Rocky Linux", lhs)
		}
		major, err := strconv.Atoi(rhs)
		if err != nil {
			return dataTypes.Data{}, errors.Wrapf(err, "unexpected major format. expected: %s, actual: %T", "int", rhs)
		}

		var fixed string
		for _, e := range a.Ranges[0].Events {
			if e.Introduced != "" && e.Introduced != "0" {
				return dataTypes.Data{}, errors.Errorf("unexpected introduced. expected: %q, actual: %q", []string{"", "0"}, e.Introduced)
			}
			if e.Fixed != "" {
				fixed = e.Fixed
			}
			if e.Limit != "" {
				return dataTypes.Data{}, errors.Errorf("unexpected limit: %q", e.Limit)
			}
			if e.LastAffected != "" {
				return dataTypes.Data{}, errors.Errorf("unexpected last_affected: %q", e.LastAffected)
			}
		}
		if fixed == "" {
			return dataTypes.Data{}, errors.New("fixed version not found")
		}

		cs[major] = append(cs[major], criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: true,
				FixStatus: &fixstatusTypes.FixStatus{
					Class: fixstatusTypes.ClassFixed,
				},
				Package: packageTypes.Package{
					// OSV Linux distros uses source package names.
					// Some adds binary names in "ecosystem_specific" fields but Rocky does not.
					// cf. https://github.com/ossf/osv-schema/issues/202
					Type: packageTypes.PackageTypeSource,
					Source: &sourcePackageTypes.Package{
						Name: a.Package.Name,
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  affectedrangeTypes.RangeTypeRPM,
					Range: []affectedrangeTypes.Range{{LessThan: fixed}},
					Fixed: []string{fixed},
				},
			},
		})
	}

	segments := func() []segment.Segment {
		ss := make([]segment.Segment, 0, len(cs))
		for major := range cs {
			ss = append(ss, segment.Segment{
				Ecosystem: ecosystem.Ecosystem(fmt.Sprintf("%s:%d", ecosystem.EcosystemTypeRocky, major)),
			})
		}
		return ss
	}()
	adv, err := func() (advisoryTypes.Advisory, error) {
		ss, err := func() ([]severityTypes.Severity, error) {
			ss := make([]severityTypes.Severity, 0, len(fetched.Severity))
			for _, s := range fetched.Severity {
				switch {
				case strings.HasPrefix(s.Score, "CVSS:3.0"):
					v30, err := cvssV30Types.Parse(s.Score)
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss3.0")
					}
					ss = append(ss, severityTypes.Severity{
						Type:    severityTypes.SeverityTypeCVSSv30,
						Source:  "osv.dev/Rocky-Linux",
						CVSSv30: v30,
					})
				case strings.HasPrefix(s.Score, "CVSS:3.1"):
					v31, err := cvssV31Types.Parse(s.Score)
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss3.1")
					}
					ss = append(ss, severityTypes.Severity{
						Type:    severityTypes.SeverityTypeCVSSv31,
						Source:  "osv.dev/Rocky-Linux",
						CVSSv31: v31,
					})
				default:
					return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", s.Score)
				}
			}
			return ss, nil
		}()
		if err != nil {
			return advisoryTypes.Advisory{}, errors.Wrapf(err, "create severity")
		}

		refs, err := func() ([]referenceTypes.Reference, error) {
			us := make(map[string]struct{})
			for _, r := range fetched.References {
				us[r.URL] = struct{}{}
			}

			dbs, err := parseDatabaseSpecific(fetched.DatabaseSpecific)
			if err != nil {
				return nil, errors.Wrap(err, "get database specific source")
			}
			if dbs.Source != "" {
				us[dbs.Source] = struct{}{}
			}

			for _, a := range fetched.Affected {
				dbs, err := parseDatabaseSpecific(a.DatabaseSpecific)
				if err != nil {
					return nil, errors.Wrap(err, "get database specific source")
				}
				if dbs.Source != "" {
					us[dbs.Source] = struct{}{}
				}
			}

			rs := make([]referenceTypes.Reference, 0, len(us))
			for u := range us {
				rs = append(rs, referenceTypes.Reference{
					URL:    u,
					Source: "osv.dev/Rocky-Linux",
				})
			}
			return rs, nil
		}()
		if err != nil {
			return advisoryTypes.Advisory{}, errors.Wrap(err, "create references")
		}

		return advisoryTypes.Advisory{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.ID),
				Title:       fetched.Summary,
				Description: fetched.Details,
				Severity:    ss,
				References:  refs,
				Published:   utiltime.Parse([]string{time.RFC3339}, fetched.Published),
				Modified:    utiltime.Parse([]string{time.RFC3339Nano}, fetched.Modified),
			},
			Segments: segments,
		}, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "create advisory")
	}

	vulns, err := func() ([]vulnerability.Vulnerability, error) {
		cves := fetched.Upstream
		if len(fetched.Upstream) == 0 {
			// "upstream" is more appropriate but some (many) OSVs use only "related", fallback to it
			cves = fetched.Related
		}
		if len(cves) == 0 {
			return nil, errors.Errorf("no CVE ID found in \"related\" or \"upstream\" fields. ID: %s", fetched.ID)
		}

		vs := make([]vulnerability.Vulnerability, 0, len(cves))
		for _, c := range cves {
			vs = append(vs, vulnerability.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(c),
				},
				Segments: segments,
			})
		}
		return vs, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrapf(err, "create vulnerabilities")
	}

	return dataTypes.Data{
		ID:              dataTypes.RootID(fetched.ID),
		Advisories:      []advisoryTypes.Advisory{adv},
		Vulnerabilities: vulns,
		Detections: func() []detectionTypes.Detection {
			ds := make([]detectionTypes.Detection, 0, len(cs))
			for major, criterions := range cs {
				ds = append(ds, detectionTypes.Detection{
					Ecosystem: ecosystem.Ecosystem(fmt.Sprintf("%s:%d", ecosystem.EcosystemTypeRocky, major)),
					Conditions: []condition.Condition{
						{
							Criteria: criteria.Criteria{
								Operator:   criteria.CriteriaOperatorTypeOR,
								Criterions: criterions,
							},
						},
					},
				})
			}
			return ds
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.RockyOSV,
			Raws: raws,
		},
	}, nil
}

func parseDatabaseSpecific(dbs any) (osv.DatabaseSpecific, error) {
	bs, err := json.Marshal(dbs)
	if err != nil {
		return osv.DatabaseSpecific{}, errors.Wrapf(err, "marshal database_specific: %+v", dbs)
	}

	var parsed osv.DatabaseSpecific
	if err := json.Unmarshal(bs, &parsed, json.RejectUnknownMembers(true)); err != nil {
		return osv.DatabaseSpecific{}, errors.Wrapf(err, "unmarshal database_specific: %+v", dbs)
	}

	return parsed, nil
}
