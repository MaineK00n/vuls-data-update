package arch

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/package"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/arch"
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
		dir: filepath.Join(util.CacheDir(), "extract", "arch"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Arch Linux")
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

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		r := utiljson.NewJSONReader()
		var fetched arch.VulnerabilityGroup
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted := extract(fetched, r.Paths())

		if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.Arch,
		Name: func() *string { t := "Arch Linux Vulnrability Group"; return &t }(),
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

func extract(fetched arch.VulnerabilityGroup, raws []string) dataTypes.Data {
	return dataTypes.Data{
		ID: fetched.Name,
		Advisories: func() []advisoryTypes.Advisory {
			as := []advisoryTypes.Advisory{{
				Content: advisoryContentTypes.Content{
					ID: fetched.Name,
					Severity: []severityTypes.Severity{{
						Type:   severityTypes.SeverityTypeVendor,
						Source: "security.archlinux.org",
						Vendor: &fetched.Severity,
					}},
					References: func() []referenceTypes.Reference {
						rs := []referenceTypes.Reference{{
							Source: "security.archlinux.org",
							URL:    fmt.Sprintf("https://security.archlinux.org/%s", fetched.Name),
						}}

						if fetched.Ticket != nil {
							rs = append(rs, referenceTypes.Reference{
								Source: "security.archlinux.org",
								URL:    fmt.Sprintf("https://bugs.archlinux.org/task/%s", *fetched.Ticket),
							})
						}

						return rs
					}(),
				},
				Ecosystems: []ecosystemTypes.Ecosystem{ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeArch)},
			}}

			for _, a := range fetched.Advisories {
				as = append(as, advisoryTypes.Advisory{
					Content: advisoryContentTypes.Content{
						ID: a,
						References: []referenceTypes.Reference{{
							Source: "security.archlinux.org",
							URL:    fmt.Sprintf("https://security.archlinux.org/%s", a),
						}},
					},
					Ecosystems: []ecosystemTypes.Ecosystem{ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeArch)},
				})
			}

			return as
		}(),
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			vs := make([]vulnerabilityTypes.Vulnerability, 0, len(fetched.Issues))
			for _, i := range fetched.Issues {
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content: vulnerabilityContentTypes.Content{
						ID: i,
						References: []referenceTypes.Reference{{
							Source: "security.archlinux.org",
							URL:    fmt.Sprintf("https://security.archlinux.org/%s", i),
						}},
					},
					Ecosystems: []ecosystemTypes.Ecosystem{ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeArch)},
				})
			}
			return vs
		}(),
		Detection: func() []detectionTypes.Detection {
			affected := affectedTypes.Affected{
				Type:  rangeTypes.RangeTypePacman,
				Range: []rangeTypes.Range{{LessEqual: fetched.Affected}},
			}
			if fetched.Fixed != nil {
				affected = affectedTypes.Affected{
					Type:  rangeTypes.RangeTypePacman,
					Range: []rangeTypes.Range{{LessThan: *fetched.Fixed}},
					Fixed: []string{*fetched.Fixed},
				}
			}

			cs := make([]criterionTypes.Criterion, 0, len(fetched.Packages))
			for _, p := range fetched.Packages {
				cs = append(cs, criterionTypes.Criterion{
					Vulnerable: true,
					Package: packageTypes.Package{
						Name: p,
					},
					Affected: &affected,
				})
			}

			return []detectionTypes.Detection{{
				Ecosystem: ecosystemTypes.Ecosystem(ecosystemTypes.EcosystemTypeArch),
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: cs,
				},
			}}
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.Arch,
			Raws: raws,
		},
	}
}
