package kev

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	kevTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev"
	vulncheckTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck"
	reportedExploitationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/reportedexploitation"
	xdbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/xdb"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/vulncheck/kev"
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
		dir: filepath.Join(util.CacheDir(), "extract", "vulncheck", "kev"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract VulnCheck KEV")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched kev.VulnCheckKEV
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		for _, cveID := range fetched.CVE {
			splitted, err := util.Split(cveID, "-", "-")
			if err != nil {
				return errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cveID)
			}
			if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", cveID)), extract(fetched, cveID, r.Paths()), true); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", cveID)))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.VulnCheckKEV,
		Name: new("VulnCheck Known Exploited Vulnerabilities"),
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

func extract(fetched kev.VulnCheckKEV, cveID string, raws []string) dataTypes.Data {
	return dataTypes.Data{
		ID: dataTypes.RootID(cveID),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
			Content: vulnerabilityContentTypes.Content{
				ID:          vulnerabilityContentTypes.VulnerabilityID(cveID),
				Title:       fetched.Name,
				Description: fetched.Description,
				KEV: &kevTypes.KEV{
					VendorProject:              fetched.VendorProject,
					Product:                    fetched.Product,
					RequiredAction:             fetched.RequiredAction,
					KnownRansomwareCampaignUse: fetched.KnownRansomwareCampaignUse,
					DateAdded:                  fetched.DateAdded,
					DueDate: func() time.Time {
						if fetched.DueDate != nil {
							return *fetched.DueDate
						}
						return time.Time{}
					}(),
					VulnCheck: func() *vulncheckTypes.VulnCheck {
						xdbs := func() []xdbTypes.XDB {
							if len(fetched.VulnCheckXDB) == 0 {
								return nil
							}
							xs := make([]xdbTypes.XDB, 0, len(fetched.VulnCheckXDB))
							for _, x := range fetched.VulnCheckXDB {
								xs = append(xs, xdbTypes.XDB{
									XDBID:       x.XDBID,
									XDBURL:      x.XDBURL,
									DateAdded:   x.DateAdded,
									ExploitType: x.ExploitType,
									CloneSSHURL: x.CloneSSHURL,
								})
							}
							return xs
						}()
						res := func() []reportedExploitationTypes.ReportedExploitation {
							if len(fetched.VulnCheckReportedExploitation) == 0 {
								return nil
							}
							es := make([]reportedExploitationTypes.ReportedExploitation, 0, len(fetched.VulnCheckReportedExploitation))
							for _, e := range fetched.VulnCheckReportedExploitation {
								es = append(es, reportedExploitationTypes.ReportedExploitation{
									URL:       e.Url,
									DateAdded: e.DateAdded,
								})
							}
							return es
						}()
						if xdbs == nil && res == nil {
							return nil
						}
						return &vulncheckTypes.VulnCheck{
							XDB:                  xdbs,
							ReportedExploitation: res,
						}
					}(),
				},
			},
		}},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.VulnCheckKEV,
			Raws: raws,
		},
	}
}
