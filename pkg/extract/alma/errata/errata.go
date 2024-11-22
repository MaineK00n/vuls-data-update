package errata

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
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
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "errata"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract AlmaLinux Errata")
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

		dir, y := filepath.Split(filepath.Dir(path))
		v := filepath.Base(filepath.Clean(dir))

		r := utiljson.NewJSONReader()
		var fetched errata.Erratum
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted := extract(fetched, v, r.Paths())

		if _, err := os.Stat(filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", extracted.ID))); err == nil {
			f, err := os.Open(filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", extracted.ID)))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", extracted.ID)))
			}
			defer f.Close()

			var base dataTypes.Data
			if err := json.NewDecoder(f).Decode(&base); err != nil {
				return errors.Wrapf(err, "decode %s", filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", extracted.ID)))
			}

			extracted.Merge(base)
		}

		if err := util.Write(filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", y, fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.AlmaErrata,
		Name: func() *string { t := "AlmaLinux Errata"; return &t }(),
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

func extract(fetched errata.Erratum, osver string, raws []string) dataTypes.Data {
	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.ID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.ID),
				Title:       fetched.Title,
				Description: fetched.Description,
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "errata.almalinux.org",
					Vendor: &fetched.Severity,
				}},
				References: func() []referenceTypes.Reference {
					m := map[referenceTypes.Reference]struct{}{{
						Source: "errata.almalinux.org",
						URL:    fmt.Sprintf("https://errata.almalinux.org/%s/%s.html", osver, strings.ReplaceAll(fetched.ID, ":", "-")),
					}: {}}
					for _, r := range fetched.References {
						m[referenceTypes.Reference{
							Source: "errata.almalinux.org",
							URL:    r.Href,
						}] = struct{}{}
					}
					return slices.Collect(maps.Keys(m))
				}(),
				Published: func() *time.Time { t := time.Unix(int64(fetched.IssuedDate), 0); return &t }(),
				Modified:  func() *time.Time { t := time.Unix(int64(fetched.UpdatedDate), 0); return &t }(),
			},
			Segments: []segmentTypes.Segment{{
				Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, osver)),
			}},
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			m := map[string]vulnerabilityContentTypes.Content{}
			for _, r := range fetched.References {
				if r.Type == "cve" {
					base, ok := m[r.ID]
					if !ok {
						base.ID = vulnerabilityContentTypes.VulnerabilityID(r.ID)
					}
					base.References = append(base.References, referenceTypes.Reference{
						Source: "errata.almalinux.org",
						URL:    r.Href,
					})
					m[r.ID] = base
				}
			}

			vs := make([]vulnerabilityTypes.Vulnerability, 0, len(m))
			for _, c := range m {
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content: c,
					Segments: []segmentTypes.Segment{{
						Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, osver)),
					}},
				})
			}
			return vs
		}(),
		Detections: func() []detectionTypes.Detection {
			modules := map[string]string{}
			for _, m := range fetched.Modules {
				modules[fmt.Sprintf("%s:%s:%s:%s:%s", m.Name, m.Stream, m.Version, m.Context, m.Arch)] = fmt.Sprintf("%s:%s", m.Name, m.Stream)
			}

			packages := map[string]map[string][]string{}
			for _, p := range fetched.Packages {
				n := p.Name
				if prefix, ok := modules[p.Module]; ok {
					n = fmt.Sprintf("%s::%s", prefix, n)
				}
				if packages[n] == nil {
					packages[n] = map[string][]string{}
				}
				packages[n][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)] = append(packages[n][fmt.Sprintf("%s:%s-%s", p.Epoch, p.Version, p.Release)], p.Arch)
			}

			cs := make([]criterionTypes.Criterion, 0, func() int {
				cap := 0
				for _, vras := range packages {
					cap += len(vras)
				}
				return cap
			}())
			for n, vras := range packages {
				for vr, as := range vras {
					cs = append(cs, criterionTypes.Criterion{
						Vulnerable: true,
						FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassFixed},
						Package: packageTypes.Package{
							Name:          n,
							Architectures: as,
						},
						Affected: &affectedTypes.Affected{
							Type:  rangeTypes.RangeTypeRPM,
							Range: []rangeTypes.Range{{LessThan: vr}},
							Fixed: []string{vr},
						},
					})
				}
			}
			return []detectionTypes.Detection{{
				Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:%s", ecosystemTypes.EcosystemTypeAlma, osver)),
				Conditions: []conditionTypes.Condition{{
					Criteria: criteriaTypes.Criteria{
						Operator:   criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: cs,
					},
				}},
			}}
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.AlmaErrata,
			Raws: raws,
		},
	}
}
