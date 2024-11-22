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
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/package"
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

		if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
			ID:   sourceTypes.Amazon,
			Name: func() *string { t := "Amazon Linux Security Center"; return &t }(),
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
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}

func extract(fetched amazon.Update, raws []string) dataTypes.Data {
	ds := detectionTypes.Detection{
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
							pkgs[p.Name] = map[string][]string{}
						}
						pkgs[p.Name][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)] = append(pkgs[p.Name][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Name, p.Release)], p.Arch)
					}

					cs := make([]criterionTypes.Criterion, 0, func() int {
						cap := 0
						for _, evras := range pkgs {
							cap += len(evras)
						}
						return cap
					}())

					repos := func() []string {
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
					}()
					for n, evras := range pkgs {
						for evr, as := range evras {
							cs = append(cs, criterionTypes.Criterion{
								Vulnerable: true,
								FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
								Package: packageTypes.Package{
									Name:          n,
									Repositories:  repos,
									Architectures: as,
								},
								Affected: &affectedTypes.Affected{
									Type:  rangeTypes.RangeTypeRPM,
									Range: []rangeTypes.Range{{LessThan: evr}},
									Fixed: []string{evr},
								},
							})
						}
					}

					return cs
				}(),
			}},
		},
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
				Published: utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Issued.Date),
				Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Updated.Date),
			},
			Segments: []segmentTypes.Segment{{Ecosystem: ds.Ecosystem}},
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
						Segments: []segmentTypes.Segment{{Ecosystem: ds.Ecosystem}},
					})
				}
			}
			return vs
		}(),
		Detections: []detectionTypes.Detection{ds},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.Amazon,
			Raws: raws,
		},
	}
}
