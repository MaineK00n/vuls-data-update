package errata

import (
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
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/rocky/errata"
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

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "rocky", "errata"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Rocky Linux Errata")

	entries, err := os.ReadDir(args)
	if err != nil {
		return errors.Wrapf(err, "read dir %s", args)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		if err := filepath.WalkDir(filepath.Join(args, entry.Name()), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			r := utiljson.NewJSONReader()
			var a errata.Advisory
			if err := r.Read(path, args, &a); err != nil {
				return errors.Wrapf(err, "read json %s", path)
			}

			if entry.Name() != "RLSA" && len(a.CVEs) == 0 {
				return nil
			}

			extracted, err := extract(a, r.Paths())
			if err != nil {
				return errors.Wrapf(err, "extract %s", path)
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
			return errors.Wrapf(err, "walk %s", args)
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.RockyErrata,
		Name: func() *string { t := "Rocky Linux Errata"; return &t }(),
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

func extract(fetched errata.Advisory, raws []string) (dataTypes.Data, error) {
	ds, err := func() ([]detectionTypes.Detection, error) {
		// vm := make(map[string]int)
		// for _, p := range fetched.AffectedProducts {
		// 	vm[p.Name] = p.MajorVersion
		// }

		type nevr struct {
			name string
			evr  string
		}
		m := make(map[int]map[nevr][]string)
		for _, p := range fetched.Packages {
			nevra := strings.Split(strings.TrimSuffix(p.NEVRA, ".rpm"), "-")
			if len(nevra) < 3 {
				return nil, errors.Errorf("unexpected nevra format. expected: %q, actual: %q", "<name>-<epoch>:<version>-<release>.<arch>", p.NEVRA)
			}
			ra := strings.Split(nevra[len(nevra)-1], ".")
			if len(ra) < 2 {
				return nil, errors.Errorf("unexpected nevra format. expected: %q, actual: %q", "<name>-<epoch>:<version>-<release>.<arch>", p.NEVRA)
			}

			name := strings.Join(nevra[:len(nevra)-2], "-")
			if p.ModuleName != nil && p.ModuleStream != nil {
				name = fmt.Sprintf("%s:%s::%s", *p.ModuleName, *p.ModuleStream, name)
			}
			evr := fmt.Sprintf("%s-%s", nevra[len(nevra)-2], strings.Join(ra[:len(ra)-1], "."))
			arch := ra[len(ra)-1]

			// If it is detected in the source package, it will cause false positives in the binary package of the unaffected arch, so do not add it.
			if arch == "src" {
				continue
			}

			// As stated in the issue, module info may be missing even though the module is a package.
			// This should be an error, but until it is corrected, it will be processed in the log and no criterion will be generated for that package.
			// https://github.com/resf/distro-tools/issues/72
			if strings.Contains(evr, ".module+el") && (p.ModuleName == nil || p.ModuleStream == nil) {
				log.Printf("[WARN] skip generating criterion for %q in %q: module package must have module info. module_name: %v, module_stream: %v", p.NEVRA, fetched.Name, p.ModuleName, p.ModuleStream)
				continue
			}

			// It would be very natural to get the major version from affected_product, but as shown in the issue below, it does not match and cannot be used.
			// https://github.com/resf/distro-tools/issues/71
			// v, ok := vm[p.ProductName]
			// if !ok {
			// 	return nil, errors.Errorf("major version of the affected product is not found. product name: %q", p.ProductName)
			// }

			lhs, _, ok := strings.Cut(strings.TrimPrefix(p.ProductName, "Rocky Linux "), " ")
			if !ok {
				return nil, errors.Errorf("unexpected product name format. expected: %q, actual: %q", "Rocky Linux <major>( SIG Cloud) <arch>", p.ProductName)
			}
			v, err := strconv.Atoi(strings.Split(lhs, ".")[0])
			if err != nil {
				return nil, errors.Wrapf(err, "unexpected product name format. expected: %q, actual: %q", "Rocky Linux <major>( SIG Cloud) <arch>", p.ProductName)
			}

			if _, ok := m[v]; !ok {
				m[v] = make(map[nevr][]string)
			}
			m[v][nevr{name: name, evr: evr}] = append(m[v][nevr{name: name, evr: evr}], arch)
		}

		ds := make([]detectionTypes.Detection, 0, len(m))
		for v, nevram := range m {
			var cs []criterionTypes.Criterion
			for nevr, as := range nevram {
				cs = append(cs, criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
						Package: packageTypes.Package{
							Type: packageTypes.PackageTypeBinary,
							Binary: &binaryPackageTypes.Package{
								Name:          nevr.name,
								Architectures: util.Unique(as),
							},
						},
						Affected: &affectedTypes.Affected{
							Type:  affectedrangeTypes.RangeTypeRPM,
							Range: []affectedrangeTypes.Range{{LessThan: nevr.evr}},
							Fixed: []string{nevr.evr},
						},
					},
				})
			}
			if len(cs) > 0 {
				ds = append(ds, detectionTypes.Detection{
					Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%d", ecosystemTypes.EcosystemTypeRocky, v)),
					Conditions: []conditionTypes.Condition{{
						Criteria: criteriaTypes.Criteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: cs,
						},
					}},
				})
			}
		}

		return ds, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk detection")
	}

	segs := func() []segmentTypes.Segment {
		ss := make([]segmentTypes.Segment, 0, len(ds))
		for _, d := range ds {
			ss = append(ss, segmentTypes.Segment{Ecosystem: d.Ecosystem})
		}
		return ss
	}()

	vs, err := func() ([]vulnerabilityTypes.Vulnerability, error) {
		vs := make([]vulnerabilityTypes.Vulnerability, 0, len(fetched.CVEs))
		for _, cve := range fetched.CVEs {
			ss, err := func() ([]severityTypes.Severity, error) {
				switch {
				case cve.CVSS3ScoringVector == "", cve.CVSS3ScoringVector == "UNKNOWN":
					return nil, nil
				case strings.HasPrefix(cve.CVSS3ScoringVector, "CVSS:3.0"):
					v30, err := cvssV30Types.Parse(cve.CVSS3ScoringVector)
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss3")
					}
					return []severityTypes.Severity{{
						Type:    severityTypes.SeverityTypeCVSSv30,
						Source:  "errata.rockylinux.org",
						CVSSv30: v30,
					}}, nil
				case strings.HasPrefix(cve.CVSS3ScoringVector, "CVSS:3.1"):
					v31, err := cvssV31Types.Parse(cve.CVSS3ScoringVector)
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss3")
					}
					return []severityTypes.Severity{{
						Type:    severityTypes.SeverityTypeCVSSv31,
						Source:  "errata.rockylinux.org",
						CVSSv31: v31,
					}}, nil
				default:
					return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", cve.CVSS3ScoringVector)
				}
			}()
			if err != nil {
				return nil, errors.Wrap(err, "walk severity")
			}

			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID:       vulnerabilityContentTypes.VulnerabilityID(cve.CVE),
					Severity: ss,
					CWE: func() []cweTypes.CWE {
						if cve.CWE == "UNKNOWN" {
							return nil
						}
						return []cweTypes.CWE{{
							Source: "errata.rockylinux.org",
							CWE:    []string{cve.CWE},
						}}
					}(),
					References: []referenceTypes.Reference{{
						Source: "errata.rockylinux.org",
						URL:    fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cve.CVE),
					}},
				},
				Segments: segs,
			})
		}
		return vs, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "walk vulnerability")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.Name),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.Name),
				Title:       fetched.Synopsis,
				Description: fetched.Description,
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "errata.rockylinux.org",
					Vendor: &fetched.Severity,
				}},
				References: func() []referenceTypes.Reference {
					rs := make([]referenceTypes.Reference, 0, 1+len(fetched.CVEs)+len(fetched.Fixes))
					rs = append(rs, referenceTypes.Reference{
						Source: "errata.rockylinux.org",
						URL:    fmt.Sprintf("https://errata.rockylinux.org/%s", fetched.Name),
					})
					for _, cve := range fetched.CVEs {
						rs = append(rs, referenceTypes.Reference{
							Source: "errata.rockylinux.org",
							URL:    fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cve.CVE),
						})
					}
					for _, fix := range fetched.Fixes {
						rs = append(rs, referenceTypes.Reference{
							Source: "errata.rockylinux.org",
							URL:    fix.Source,
						})
					}
					return rs
				}(),
				Published: utiltime.Parse([]string{time.RFC3339Nano}, fetched.PublishedAt),
			},
			Segments: segs,
		}},
		Vulnerabilities: vs,
		Detections:      ds,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.RockyErrata,
			Raws: raws,
		},
	}, nil
}
