package secdb

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	sourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/secdb"
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
		dir: filepath.Join(util.CacheDir(), "extract", "alpine", "secdb"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Alpine Linux SecDB")
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
		var fetched secdb.Advisory
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		for _, data := range extract(fetched, r.Paths()) {
			if _, err := os.Stat(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID))); err == nil {
				f, err := os.Open(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID)))
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID)))
				}
				defer f.Close()

				var base dataTypes.Data
				if err := json.NewDecoder(f).Decode(&base); err != nil {
					return errors.Wrapf(err, "decode %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID)))
				}

				data.Merge(base)
			}

			if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fmt.Sprintf("%s.json", data.ID)))
			}
		}

		if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
			ID:   sourceTypes.AlpineSecDB,
			Name: func() *string { t := "Alpine Linux Security Fixes Database"; return &t }(),
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

func extract(fetched secdb.Advisory, raws []string) []dataTypes.Data {
	m := make(map[string][]criterionTypes.Criterion)
	for _, pkg := range fetched.Packages {
		for v, ids := range pkg.Pkg.Secfixes {
			for _, id := range ids {
				m[id] = append(m[id], criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
						Package: packageTypes.Package{
							Type: packageTypes.PackageTypeSource,
							Source: &sourcePackageTypes.Package{
								Name:         pkg.Pkg.Name,
								Repositories: []string{fetched.Reponame},
							},
						},
						Affected: &affectedTypes.Affected{
							Type:  rangeTypes.RangeTypeAPK,
							Range: []rangeTypes.Range{{LessThan: v}},
							Fixed: []string{v},
						},
					},
				})
			}
		}
	}

	ds := make([]dataTypes.Data, 0, len(m))
	for id, cs := range m {
		ds = append(ds, dataTypes.Data{
			ID: dataTypes.RootID(id),
			Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(id),
					References: []referenceTypes.Reference{{
						Source: "security.alpinelinux.org",
						URL:    fmt.Sprintf("https://security.alpinelinux.org/vuln/%s", id),
					}},
				},
				Segments: []segmentTypes.Segment{{
					Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlpine, strings.TrimPrefix(fetched.Distroversion, "v"))),
				}},
			}},
			Detections: []detectionTypes.Detection{{
				Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlpine, strings.TrimPrefix(fetched.Distroversion, "v"))),
				Conditions: []conditionTypes.Condition{{
					Criteria: criteriaTypes.Criteria{
						Operator:   criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: cs,
					},
				}},
			}},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.AlpineSecDB,
				Raws: raws,
			},
		})
	}
	return ds
}
