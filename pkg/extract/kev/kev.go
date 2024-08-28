package kev

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	kevTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/kev"
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
		dir: filepath.Join(util.CacheDir(), "extract", "kev"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Known Exploited Vulnerabilities Catalog")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		jsonReader := utiljson.NewJSONReader()
		var fetched kev.Vulnerability
		if err := jsonReader.Read(path, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted := extract(fetched, jsonReader.Paths())

		if err := util.Write(filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.KEV,
		Name: func() *string { t := "CISA Catalog of Known Exploited Vulnerabilities"; return &t }(),
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

func extract(fetched kev.Vulnerability, raws []string) dataTypes.Data {
	return dataTypes.Data{
		ID: fetched.CveID,
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
			Content: vulnerabilityContentTypes.Content{
				ID:          fetched.CveID,
				Title:       fetched.VulnerabilityName,
				Description: fetched.ShortDescription,
				CWE: func() []cweTypes.CWE {
					if len(fetched.CWEs) == 0 {
						return nil
					}
					return []cweTypes.CWE{{
						Source: "cisa.gov/kev",
						CWE:    fetched.CWEs,
					}}
				}(),
				KEV: &kevTypes.KEV{
					VendorProject:              fetched.VendorProject,
					Product:                    fetched.Product,
					RequiredAction:             fetched.RequiredAction,
					KnownRansomwareCampaignUse: fetched.KnownRansomwareCampaignUse,
					Notes:                      fetched.Notes,
					DateAdded: func() time.Time {
						if t := utiltime.Parse([]string{"2006-01-02"}, fetched.DateAdded); t != nil {
							return *t
						}
						return time.Time{}
					}(),
					DueDate: func() time.Time {
						if t := utiltime.Parse([]string{"2006-01-02"}, fetched.DueDate); t != nil {
							return *t
						}
						return time.Time{}
					}(),
				},
			},
		}},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.KEV,
			Raws: raws,
		},
	}
}
