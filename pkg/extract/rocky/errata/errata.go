package errata

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
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
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
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

		extracted, err := extract(a, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", extracted.ID)
		}

		splitted, err := util.Split(string(extracted.ID), "-", ":")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", extracted.ID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "RLSA-yyyy:\\d{4}", extracted.ID)
		}

		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
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
		ds := make([]detectionTypes.Detection, 0, len(fetched.Rpms))
		for product, rpms := range fetched.Rpms {
			cs, err := func() ([]criterionTypes.Criterion, error) {
				m := make(map[string]map[string][]string)
				for _, rpm := range rpms.NVRAS {
					nvr := strings.Split(strings.TrimSuffix(rpm, ".rpm"), "-")
					if len(nvr) < 3 {
						return nil, errors.Errorf("unexpected nvras format. expected: %q, actual: %q", "<name>-<version>-<release>.<arch>", rpm)
					}
					ra := strings.Split(nvr[len(nvr)-1], ".")
					if len(ra) < 2 {
						return nil, errors.Errorf("unexpected nvras format. expected: %q, actual: %q", "<name>-<version>-<release>.<arch>", rpm)
					}

					name := strings.Join(nvr[:len(nvr)-2], "-")
					ver := fmt.Sprintf("%s-%s", nvr[len(nvr)-2], strings.Join(ra[:len(ra)-1], "."))
					arch := ra[len(ra)-1]
					// If it is detected in the source package, it will cause false positives in the binary package of the unaffected arch, so do not add it.
					if arch == "src" {
						continue
					}

					if _, ok := m[name]; !ok {
						m[name] = make(map[string][]string)
					}
					m[name][ver] = append(m[name][ver], arch)
				}

				var cs []criterionTypes.Criterion
				for name, vram := range m {
					for vr, as := range vram {
						// since the modularitylabel is unknown, the module package criterion is not created
						if strings.Contains(vr, ".module+el") {
							continue
						}

						cs = append(cs, criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
								Package: packageTypes.Package{
									Type: packageTypes.PackageTypeBinary,
									Binary: &binaryPackageTypes.Package{
										Name:          name,
										Architectures: as,
									},
								},
								Affected: &affectedTypes.Affected{
									Type:  affectedrangeTypes.RangeTypeRPM,
									Range: []affectedrangeTypes.Range{{LessThan: vr}},
									Fixed: []string{vr},
								},
							},
						})
					}
				}
				return cs, nil
			}()
			if err != nil {
				return nil, errors.Wrap(err, "walk nvras")
			}

			if len(cs) > 0 {
				ds = append(ds, detectionTypes.Detection{
					Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeRocky, strings.TrimPrefix(strings.TrimPrefix(product, "Rocky Linux "), "SIG Cloud "))),
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
		vs := make([]vulnerabilityTypes.Vulnerability, 0, len(fetched.Cves))
		for _, cve := range fetched.Cves {
			ss, err := func() ([]severityTypes.Severity, error) {
				if cve.Cvss3ScoringVector == "UNKNOWN" {
					return nil, nil
				}
				switch {
				case strings.HasPrefix(cve.Cvss3ScoringVector, "CVSS:3.0"):
					v30, err := cvssV30Types.Parse(cve.Cvss3ScoringVector)
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss3")
					}
					return []severityTypes.Severity{{
						Type:    severityTypes.SeverityTypeCVSSv30,
						Source:  cve.SourceBy,
						CVSSv30: v30,
					}}, nil
				case strings.HasPrefix(cve.Cvss3ScoringVector, "CVSS:3.1"):
					v31, err := cvssV31Types.Parse(cve.Cvss3ScoringVector)
					if err != nil {
						return nil, errors.Wrap(err, "parse cvss3")
					}
					return []severityTypes.Severity{{
						Type:    severityTypes.SeverityTypeCVSSv31,
						Source:  cve.SourceBy,
						CVSSv31: v31,
					}}, nil
				default:
					return nil, errors.Errorf("unexpected CVSSv3 string. expected: %q, actual: %q", "<score>/CVSS:3.[01]/<vector>", cve.Cvss3ScoringVector)
				}
			}()
			if err != nil {
				return nil, errors.Wrap(err, "walk severity")
			}

			vs = append(vs, vulnerabilityTypes.Vulnerability{
				Content: vulnerabilityContentTypes.Content{
					ID:       vulnerabilityContentTypes.VulnerabilityID(cve.Name),
					Severity: ss,
					CWE: func() []cweTypes.CWE {
						if cve.Cwe == "UNKNOWN" {
							return nil
						}
						return []cweTypes.CWE{{
							Source: cve.SourceBy,
							CWE:    []string{cve.Cwe},
						}}
					}(),
					References: []referenceTypes.Reference{{
						Source: cve.SourceBy,
						URL:    cve.SourceLink,
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
					Vendor: func() *string { s := strings.TrimPrefix(fetched.Severity, "SEVERITY_"); return &s }(),
				}},
				References: func() []referenceTypes.Reference {
					rs := make([]referenceTypes.Reference, 0, 1+len(fetched.Cves)+len(fetched.Fixes))
					rs = append(rs, referenceTypes.Reference{
						Source: "errata.rockylinux.org",
						URL:    fmt.Sprintf("https://errata.rockylinux.org/%s", fetched.Name),
					})
					for _, cve := range fetched.Cves {
						rs = append(rs, referenceTypes.Reference{
							Source: cve.SourceBy,
							URL:    cve.SourceLink,
						})
					}
					for _, fix := range fetched.Fixes {
						rs = append(rs, referenceTypes.Reference{
							Source: fix.SourceBy,
							URL:    fix.SourceLink,
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
