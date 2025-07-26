package tracker

import (
	"fmt"
	"io/fs"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
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
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/tracker"
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
		dir: filepath.Join(util.CacheDir(), "extract", "ubuntu", "ubuntu-cve-tracker"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Ubuntu CVE Tracker")
	for _, target := range []string{"active", "retired"} {
		if err := filepath.WalkDir(filepath.Join(args, target), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}

			r := utiljson.NewJSONReader()
			var fetched tracker.Advisory
			if err := r.Read(path, args, &fetched); err != nil {
				return errors.Wrapf(err, "read %s", path)
			}

			extracted, err := extract(fetched, r.Paths())
			if err != nil {
				return errors.Wrapf(err, "extract %s", path)
			}

			ss, err := util.Split(string(extracted.ID), "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", extracted.ID)
			}

			if err := util.Write(filepath.Join(options.dir, "data", ss[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", ss[1], fmt.Sprintf("%s.json", extracted.ID)))
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", args)
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.UbuntuCVETracker,
		Name: func() *string { t := "Ubuntu CVE Tracker"; return &t }(),
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

func extract(fetched tracker.Advisory, paths []string) (dataTypes.Data, error) {
	type rp struct {
		criterion criterionTypes.Criterion
		priority  string
	}
	rpm := make(map[string]map[string]rp)
	for pn, p := range fetched.Packages {
		for rn, r := range p.Releases {
			if rpm[rn] == nil {
				rpm[rn] = make(map[string]rp)
			}
			switch r.Status {
			case "released":
				rpm[rn][pn] = rp{
					criterion: criterionTypes.Criterion{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
							Package: vcPackageTypes.Package{
								Type:   vcPackageTypes.PackageTypeSource,
								Source: &vcSourcePackageTypes.Package{Name: pn},
							},
							Affected: &vcAffectedTypes.Affected{
								Type:  vcAffectedRangeTypes.RangeTypeDPKG,
								Range: []vcAffectedRangeTypes.Range{{LessThan: r.Note}},
								Fixed: []string{r.Note},
							},
						},
					},
					priority: func() string {
						if r.Priority != nil {
							return r.Priority.Priority
						}
						if p.Priority != nil {
							return p.Priority.Priority
						}
						if fetched.Priority != nil {
							return fetched.Priority.Priority
						}
						return ""
					}(),
				}
			case "deferred", "pending", "ignored", "in-progress", "needed":
				rpm[rn][pn] = rp{
					criterion: criterionTypes.Criterion{
						Type: criterionTypes.CriterionTypeVersion,
						Version: &vcTypes.Criterion{
							Vulnerable: true,
							FixStatus: &vcFixStatusTypes.FixStatus{
								Class: vcFixStatusTypes.ClassUnfixed,
								Vendor: func() string {
									if r.Note != "" {
										return fmt.Sprintf("%s: %s", r.Status, r.Note)
									}
									return r.Status
								}(),
							},
							Package: vcPackageTypes.Package{
								Type:   vcPackageTypes.PackageTypeSource,
								Source: &vcSourcePackageTypes.Package{Name: pn},
							},
						},
					},
					priority: func() string {
						if r.Priority != nil {
							return r.Priority.Priority
						}
						if p.Priority != nil {
							return p.Priority.Priority
						}
						if fetched.Priority != nil {
							return fetched.Priority.Priority
						}
						return ""
					}(),
				}
			case "not-affected", "needs-triage", "DNE":
			default:
				return dataTypes.Data{}, errors.Errorf("unexpected package status. expected: %q, actual: %q", []string{"released", "deferred", "pending", "ignored", "in-progress", "needed", "not-affected", "needs-triage", "DNE"}, r.Status)
			}
		}
	}

	extracted := dataTypes.Data{
		ID: dataTypes.RootID(fetched.Candidate),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.UbuntuCVETracker,
			Raws: paths,
		},
	}

	baseVC := vulnerabilityContentTypes.Content{
		ID:          vulnerabilityContentTypes.VulnerabilityID(fetched.Candidate),
		Description: fetched.Description,
		References: func() []referenceTypes.Reference {
			rs := make([]referenceTypes.Reference, 0, len(fetched.References))
			for _, r := range fetched.References {
				rs = append(rs, referenceTypes.Reference{
					Source: "launchpad.net/ubuntu-cve-tracker",
					URL:    r,
				})
			}
			return rs
		}(),
		Published: utiltime.Parse([]string{"2006-01-02 15:04:05 MST", "2006-01-02"}, fetched.PublicDate),
		Optional: func() map[string]interface{} {
			if fetched.UbuntuDescription != "" {
				return map[string]interface{}{"ubuntu_description": fetched.UbuntuDescription}
			}
			return nil
		}(),
	}

	m := make(map[segmentTypes.Segment][]criterionTypes.Criterion)
	for rn, pm := range rpm {
		v, err := func(release string) (string, error) {
			rtov := map[string]string{
				"upstream": "",
				"devel":    "",
				"snap":     "snap",
				"warty":    "4.10",
				"hoary":    "5.04",
				"breezy":   "5.10",
				"dapper":   "6.06",
				"edgy":     "6.10",
				"feisty":   "7.04",
				"gutsy":    "7.10",
				"hardy":    "8.04",
				"intrepid": "8.10",
				"jaunty":   "9.04",
				"karmic":   "9.10",
				"lucid":    "10.04",
				"maverick": "10.10",
				"natty":    "11.04",
				"oneiric":  "11.10",
				"precise":  "12.04",
				"quantal":  "12.10",
				"raring":   "13.04",
				"saucy":    "13.10",
				"trusty":   "14.04",
				"utopic":   "14.10",
				"vivid":    "15.04",
				"wily":     "15.10",
				"xenial":   "16.04",
				"yakkety":  "16.10",
				"zesty":    "17.04",
				"artful":   "17.10",
				"bionic":   "18.04",
				"cosmic":   "18.10",
				"disco":    "19.04",
				"eoan":     "19.10",
				"focal":    "20.04",
				"groovy":   "20.10",
				"hirsute":  "21.04",
				"impish":   "21.10",
				"jammy":    "22.04",
				"kinetic":  "22.10",
				"lunar":    "23.04",
				"mantic":   "23.10",
				"noble":    "24.04",
				"oracular": "24.10",
				"plucky":   "25.04",
			}

			for s := range strings.SplitSeq(release, "/") {
				v, ok := rtov[s]
				if ok {
					return v, nil
				}
			}
			return "", errors.Errorf("unexpected release name. expected: %q, actual: %q", slices.Collect(maps.Keys(rtov)), release)
		}(rn)
		if err != nil {
			log.Printf("[WARN] failed to find version from release. err: %s", err)
			continue
		}
		if v == "" {
			continue
		}

		for _, rp := range pm {
			seg := segmentTypes.Segment{
				Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeUbuntu, v)),
				Tag: segmentTypes.DetectionTag(func() string {
					if rp.priority != "" {
						return fmt.Sprintf("%s_%s", rn, rp.priority)
					}
					return rn
				}()),
			}

			vc := baseVC
			if rp.priority != "" {
				vc.Severity = append(vc.Severity, severityTypes.Severity{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "launchpad.net/ubuntu-cve-tracker",
					Vendor: &rp.priority,
				})
			}

			switch i := slices.IndexFunc(extracted.Vulnerabilities, func(e vulnerabilityTypes.Vulnerability) bool {
				return vulnerabilityContentTypes.Compare(e.Content, vc) == 0
			}); i {
			case -1:
				extracted.Vulnerabilities = append(extracted.Vulnerabilities, vulnerabilityTypes.Vulnerability{
					Content:  vc,
					Segments: []segmentTypes.Segment{seg},
				})
			default:
				if !slices.Contains(extracted.Vulnerabilities[i].Segments, seg) {
					extracted.Vulnerabilities[i].Segments = append(extracted.Vulnerabilities[i].Segments, seg)
				}
			}

			m[seg] = append(m[seg], rp.criterion)
		}
	}

	for seg, cns := range m {
		switch i := slices.IndexFunc(extracted.Detections, func(e detectionTypes.Detection) bool {
			return e.Ecosystem == seg.Ecosystem
		}); i {
		case -1:
			extracted.Detections = append(extracted.Detections, detectionTypes.Detection{
				Ecosystem: seg.Ecosystem,
				Conditions: []conditionTypes.Condition{{
					Criteria: criteriaTypes.Criteria{
						Operator:   criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: cns,
					},
					Tag: seg.Tag,
				}},
			})
		default:
			extracted.Detections[i].Conditions = append(extracted.Detections[i].Conditions, conditionTypes.Condition{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: cns,
				},
				Tag: seg.Tag,
			})
		}
	}

	if len(extracted.Detections) == 0 {
		vc := baseVC
		if fetched.Priority != nil {
			vc.Severity = append(vc.Severity, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeVendor,
				Source: "launchpad.net/ubuntu-cve-tracker",
				Vendor: &fetched.Priority.Priority,
			})
		}
		extracted.Vulnerabilities = append(extracted.Vulnerabilities, vulnerabilityTypes.Vulnerability{Content: vc})
	}

	return extracted, nil
}
