package amazon

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/amazon"
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
		dir: filepath.Join(util.CacheDir(), "extract", "amazon"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Amazon Linux")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched amazon.Update
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted := extract(fetched, r.Paths())

		dir, y := filepath.Split(filepath.Dir(path))
		dir, repo := filepath.Split(filepath.Clean(dir))
		if filepath.Base(dir) == "extras" {
			dir = filepath.Dir(filepath.Clean(dir))
			repo = filepath.Join("extras", repo)
		}
		if err := util.Write(filepath.Join(options.dir, "data", filepath.Base(dir), repo, y, fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", filepath.Base(dir), repo, y, fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.Amazon,
		Name: new("Amazon Linux Security Center"),
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

func extract(fetched amazon.Update, raws []string) dataTypes.Data {
	d := detectionTypes.Detection{
		Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAmazon, func() string {
			switch {
			case strings.HasPrefix(fetched.ID, "ALAS2023"):
				return "2023"
			case strings.HasPrefix(fetched.ID, "ALAS2022"):
				return "2022"
			case strings.HasPrefix(fetched.ID, "ALAS2"):
				return "2"
			default:
				return "1"
			}
		}())),
		Conditions: []conditionTypes.Condition{{
			Criteria: criteriaTypes.Criteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: func() []criterionTypes.Criterion {
					pkgs := make(map[string]map[string][]string)
					for _, p := range fetched.Pkglist.Collection.Package {
						if pkgs[p.Name] == nil {
							pkgs[p.Name] = make(map[string][]string)
						}
						pkgs[p.Name][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)] = append(pkgs[p.Name][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)], p.Arch)
					}

					cs := make([]criterionTypes.Criterion, 0, func() int {
						cap := 0
						for _, evras := range pkgs {
							cap += len(evras)
						}
						return cap
					}())

					for n, evras := range pkgs {
						for evr, as := range evras {
							cs = append(cs, criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
									Package: packageTypes.Package{
										Type: packageTypes.PackageTypeBinary,
										Binary: &binaryPackageTypes.Package{
											Name:          n,
											Architectures: as,
										},
									},
									Affected: &affectedTypes.Affected{
										Type:  rangeTypes.RangeTypeRPM,
										Range: []rangeTypes.Range{{LessThan: evr}},
										Fixed: []string{evr},
									},
								},
							})
						}
					}

					return cs
				}(),
				Repositories: func() []string {
					switch {
					case strings.HasPrefix(fetched.ID, "ALAS2023"):
						if repo, ok := strings.CutPrefix(fetched.Pkglist.Collection.Short, "amazon-linux-2023---"); ok {
							return []string{repo}
						}
						return []string{"amazonlinux"}
					case strings.HasPrefix(fetched.ID, "ALAS2022"):
						return []string{"amazonlinux"}
					case strings.HasPrefix(fetched.ID, "ALAS2"):
						if repo, ok := strings.CutPrefix(fetched.Pkglist.Collection.Short, "amazon-linux-2---"); ok {
							return []string{fmt.Sprintf("amzn2extra-%s", repo)}
						}
						return []string{"amzn2-core"}
					default:
						return []string{"amzn-main", "amzn-updates"}
					}
				}(),
			}},
		},
	}

	// These 9 AL2023 advisories (ALAS-935..1080) contain kernel6.12 packages
	// alongside unsuffixed shared packages (bpftool, kernel-tools, etc.) that
	// are also used by the kernel 6.1 branch. Starting from ALAS-1129, Amazon
	// renamed 6.12-branch packages with a "6.12" suffix. For these 9 earlier
	// advisories, wrap the shared packages in an AND criteria requiring
	// kernel6.12 to be installed, preventing false positives for 6.1 users.
	// See applyKernel612Guard for the definition of "shared" packages.
	switch fetched.ID {
	case "ALAS2023-2025-935",
		"ALAS2023-2025-940",
		"ALAS2023-2025-948",
		"ALAS2023-2025-984",
		"ALAS2023-2025-994",
		"ALAS2023-2025-995",
		"ALAS2023-2025-1052",
		"ALAS2023-2025-1053",
		"ALAS2023-2025-1080":
		d.Conditions[0].Criteria = applyKernel612Guard(d.Conditions[0].Criteria)
	default:
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.ID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.ID),
				Title:       fetched.Title,
				Description: fetched.Description,
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: fetched.Author,
					Vendor: &fetched.Severity,
				}},
				References: func() []referenceTypes.Reference {
					rs := []referenceTypes.Reference{{
						Source: fetched.Author,
						URL: func() string {
							switch {
							case strings.HasPrefix(fetched.ID, "ALAS2023"):
								return fmt.Sprintf("https://alas.aws.amazon.com/AL2023/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS2023"))
							case strings.HasPrefix(fetched.ID, "ALAS2022"):
								return fmt.Sprintf("https://alas.aws.amazon.com/AL2022/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS2022"))
							case strings.HasPrefix(fetched.ID, "ALAS2"):
								return fmt.Sprintf("https://alas.aws.amazon.com/AL2/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS2"))
							default:
								return fmt.Sprintf("https://alas.aws.amazon.com/ALAS%s.html", strings.TrimPrefix(fetched.ID, "ALAS"))
							}
						}(),
					}}
					for _, r := range fetched.References.Reference {
						rs = append(rs, referenceTypes.Reference{
							Source: fetched.Author,
							URL:    r.Href,
						})
					}
					return rs
				}(),
				Published: utiltime.Parse([]string{"2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "2006-01-02 15:04"}, fetched.Issued.Date),
				Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "2006-01-02 15:04"}, fetched.Updated.Date),
			},
			Segments: []segmentTypes.Segment{{Ecosystem: d.Ecosystem}},
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			var vs []vulnerabilityTypes.Vulnerability
			for _, r := range fetched.References.Reference {
				if r.Type == "cve" {
					vs = append(vs, vulnerabilityTypes.Vulnerability{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID(r.ID),
							References: []referenceTypes.Reference{{
								Source: fetched.Author,
								URL:    r.Href,
							}},
						},
						Segments: []segmentTypes.Segment{{Ecosystem: d.Ecosystem}},
					})
				}
			}
			return vs
		}(),
		Detections: []detectionTypes.Detection{d},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.Amazon,
			Raws: raws,
		},
	}
}

// applyKernel612Guard restructures criteria for the 9 AL2023 advisories
// (ALAS-935..1080) that contain kernel6.12 alongside unsuffixed shared packages.
//
// "Shared" means the package name is common to both the kernel 6.1 and
// kernel 6.12 branches in AL2023. For example, kernel-tools and bpftool are
// built from both branches but use the same unsuffixed name, whereas
// kernel6.12, perf6.12, etc. are unique to the 6.12 branch. Reusing the same
// name for both branches was arguably a poor packaging strategy; Amazon
// recognised this and, starting from ALAS-1129, renamed the 6.12-branch
// packages with an explicit "6.12" suffix. Because of this rename the set of
// advisories that need this guard is fixed to the 9 listed above and will not
// grow (at least not for this reason).
//
// This function moves shared packages (bpftool*, kernel-*) into a nested AND
// criteria guarded by a kernel6.12 existence check (vulnerable:false, ge 0),
// so that they match only when kernel6.12 is actually installed on the host,
// preventing false positives on kernel 6.1 systems.
func applyKernel612Guard(criteria criteriaTypes.Criteria) criteriaTypes.Criteria {
	var nonShared, shared []criterionTypes.Criterion
	for _, c := range criteria.Criterions {
		if c.Type == criterionTypes.CriterionTypeVersion &&
			c.Version != nil &&
			c.Version.Package.Binary != nil &&
			isKernel612SharedPackage(c.Version.Package.Binary.Name) {
			shared = append(shared, c)
		} else {
			nonShared = append(nonShared, c)
		}
	}
	if len(shared) == 0 {
		return criteria
	}

	criteria.Criterions = nonShared
	criteria.Criterias = append(criteria.Criterias, criteriaTypes.Criteria{
		Operator: criteriaTypes.CriteriaOperatorTypeAND,
		Criterions: []criterionTypes.Criterion{{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: false,
				Package: packageTypes.Package{
					Type: packageTypes.PackageTypeBinary,
					Binary: &binaryPackageTypes.Package{
						Name: "kernel6.12",
					},
				},
				Affected: &affectedTypes.Affected{
					Type:  rangeTypes.RangeTypeRPM,
					Range: []rangeTypes.Range{{GreaterEqual: "0"}},
				},
			},
		}},
		Criterias: []criteriaTypes.Criteria{{
			Operator:   criteriaTypes.CriteriaOperatorTypeOR,
			Criterions: shared,
		}},
	})
	return criteria
}

// isKernel612SharedPackage reports whether the package name is a kernel-related
// package shared between the kernel 6.1 and 6.12 branches in Amazon Linux 2023.
// These are packages like bpftool, kernel-devel, kernel-tools whose names do not
// distinguish which kernel branch they belong to.
func isKernel612SharedPackage(name string) bool {
	return (strings.HasPrefix(name, "kernel-") || strings.HasPrefix(name, "bpftool")) &&
		!strings.Contains(name, "6.12")
}
