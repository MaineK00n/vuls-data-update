package kev

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	kevTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev"
	enisaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/enisa"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/enisa/kev"
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
		dir: filepath.Join(util.CacheDir(), "extract", "enisa", "kev"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract ENISA Known Exploited Vulnerabilities")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched kev.Vulnerability
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted := extract(fetched, r.Paths())

		splitted, err := util.Split(fetched.EUVDID, "-", "-")
		if err != nil {
			return errors.Errorf("unexpected EUVD ID format. expected: %q, actual: %q", "EUVD-yyyy-\\d{4,}", fetched.EUVDID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Errorf("unexpected EUVD ID format. expected: %q, actual: %q", "EUVD-yyyy-\\d{4,}", fetched.EUVDID)
		}
		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.ENISAKEV,
		Name: new("ENISA Known Exploited Vulnerabilities"),
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

func sanitize(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func extract(fetched kev.Vulnerability, raws []string) dataTypes.Data {
	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.EUVDID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID: advisoryContentTypes.AdvisoryID(fetched.EUVDID),
				KEV: &kevTypes.KEV{
					VendorProject: fetched.VendorProject,
					Product:       fetched.Product,
					Notes:         sanitize(fetched.Notes),
					ENISA: func() *enisaTypes.ENISA {
						e := enisaTypes.ENISA{
							DateReported: func() time.Time {
								if t := utiltime.Parse([]string{"02/01/06"}, fetched.DateReported); t != nil {
									return *t
								}
								return time.Time{}
							}(),
							PatchedSince:           sanitize(fetched.PatchedSince),
							OriginSource:           sanitize(fetched.OriginSource),
							ExploitationType:       sanitize(fetched.ExploitationType),
							ThreatActorsExploiting: sanitize(fetched.ThreatActorsExploiting),
						}
						if (e == enisaTypes.ENISA{}) {
							return nil
						}
						return &e
					}(),
				},
			},
		}},
		Vulnerabilities: func() []vulnerabilityTypes.Vulnerability {
			if fetched.CVEID == "" {
				return nil
			}
			return []vulnerabilityTypes.Vulnerability{{
				Content: vulnerabilityContentTypes.Content{
					ID:          vulnerabilityContentTypes.VulnerabilityID(fetched.CVEID),
					Title:       sanitize(fetched.VulnerabilityName),
					Description: sanitize(fetched.ShortDescription),
					CWE: func() []cweTypes.CWE {
						if sanitize(fetched.CWEs) == "" {
							return nil
						}
						return []cweTypes.CWE{{
							Source: "enisa.europa.eu/kev",
							CWE:    []string{sanitize(fetched.CWEs)},
						}}
					}(),
				},
			}}
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.ENISAKEV,
			Raws: raws,
		},
	}
}
