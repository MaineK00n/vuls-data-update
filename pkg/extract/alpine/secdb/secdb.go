package secdb

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria/criterion"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria/criterion/affected"
	affectedrange "github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria/criterion/affected/range"
	criterionpackage "github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection/criteria/criterion/package"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/vulnerability"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
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

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var fetched secdb.Advisory
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		for _, data := range extract(fetched) {
			if err := util.Write(filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", data.ID)))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}

func extract(fetched secdb.Advisory) []types.Data {
	m := map[string]types.Data{}
	for _, pkg := range fetched.Packages {
		for v, ids := range pkg.Pkg.Secfixes {
			for _, id := range ids {
				d, ok := m[id]
				if !ok {
					d = types.Data{
						ID: id,
						Vulnerabilities: []vulnerability.Vulnerability{{
							ID: id,
							References: []reference.Reference{{
								Source: "security.alpinelinux.org",
								URL:    fmt.Sprintf("https://security.alpinelinux.org/vuln/%s", id),
							}},
						}},
						DataSource: source.AlpineSecDB,
					}
				}

				c := criterion.Criterion{
					Vulnerable: true,
					Package: criterionpackage.Package{
						Name:          pkg.Pkg.Name,
						Repositories:  []string{fetched.Reponame},
						Architectures: fetched.Archs,
					},
					Affected: &affected.Affected{
						Type:  affectedrange.RangeTypeAPK,
						Range: []affectedrange.Range{{LessThan: v}},
						Fixed: []string{v},
					},
				}

				switch index := slices.IndexFunc(d.Detection, func(e detection.Detection) bool {
					return e.Ecosystem == fmt.Sprintf("%s:%s", detection.EcosystemTypeAlpine, strings.TrimPrefix(fetched.Distroversion, "v"))
				}); index {
				case -1:
					d.Detection = []detection.Detection{
						{
							Ecosystem: fmt.Sprintf("%s:%s", detection.EcosystemTypeAlpine, strings.TrimPrefix(fetched.Distroversion, "v")),
							Criteria: criteria.Criteria{
								Operator:   criteria.CriteriaOperatorTypeOR,
								Criterions: []criterion.Criterion{c},
							},
						},
					}
				default:
					d.Detection[index].Criteria.Criterions = append(d.Detection[index].Criteria.Criterions, c)

				}
				m[id] = d
			}
		}
	}
	return maps.Values(m)
}
