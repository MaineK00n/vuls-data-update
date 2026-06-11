package list

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/enisa/euvd/list"
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
		dir: filepath.Join(util.CacheDir(), "extract", "enisa", "euvd", "list"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract European Union Vulnerability Database (EUVD) List")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched list.Item
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		splitted, err := util.Split(fetched.ID, "-", "-")
		if err != nil {
			return errors.Errorf("unexpected EUVD ID format. expected: %q, actual: %q", "EUVD-yyyy-...", fetched.ID)
		}
		if splitted[0] != "EUVD" {
			return errors.Errorf("unexpected EUVD ID format. expected: %q, actual: %q", "EUVD-yyyy-...", fetched.ID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Errorf("unexpected EUVD ID format. expected: %q, actual: %q", "EUVD-yyyy-...", fetched.ID)
		}
		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.ENISAEUVDList,
		Name: new("European Union Vulnerability Database (EUVD) List"),
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

func extract(fetched list.Item, raws []string) (dataTypes.Data, error) {
	severity, err := func() ([]severityTypes.Severity, error) {
		switch {
		case fetched.BaseScoreVector == "":
			return nil, nil
		case strings.HasPrefix(fetched.BaseScoreVector, "CVSS:3.0/"):
			v30, err := v30Types.Parse(fetched.BaseScoreVector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss v3.0 vector %s", fetched.BaseScoreVector)
			}
			return []severityTypes.Severity{{
				Type:    severityTypes.SeverityTypeCVSSv30,
				Source:  "euvd.enisa.europa.eu",
				CVSSv30: v30,
			}}, nil
		case strings.HasPrefix(fetched.BaseScoreVector, "CVSS:3.1/"):
			v31, err := v31Types.Parse(fetched.BaseScoreVector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss v3.1 vector %s", fetched.BaseScoreVector)
			}
			return []severityTypes.Severity{{
				Type:    severityTypes.SeverityTypeCVSSv31,
				Source:  "euvd.enisa.europa.eu",
				CVSSv31: v31,
			}}, nil
		case strings.HasPrefix(fetched.BaseScoreVector, "CVSS:4.0/"):
			v40, err := v40Types.Parse(fetched.BaseScoreVector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss v4.0 vector %s", fetched.BaseScoreVector)
			}
			return []severityTypes.Severity{{
				Type:    severityTypes.SeverityTypeCVSSv40,
				Source:  "euvd.enisa.europa.eu",
				CVSSv40: v40,
			}}, nil
		default:
			v2, err := v2Types.Parse(fetched.BaseScoreVector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss v2 vector %s", fetched.BaseScoreVector)
			}
			return []severityTypes.Severity{{
				Type:   severityTypes.SeverityTypeCVSSv2,
				Source: "euvd.enisa.europa.eu",
				CVSSv2: v2,
			}}, nil
		}
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "parse severity")
	}

	advisories, vulnerabilities, err := func() ([]advisoryTypes.Advisory, []vulnerabilityTypes.Vulnerability, error) {
		var as []advisoryTypes.Advisory
		var vs []vulnerabilityTypes.Vulnerability
		for a := range strings.SplitSeq(fetched.Aliases, "\n") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			switch {
			case strings.HasPrefix(a, "CVE-"):
				vs = append(vs, vulnerabilityTypes.Vulnerability{
					Content: vulnerabilityContentTypes.Content{
						ID: vulnerabilityContentTypes.VulnerabilityID(a),
					},
				})
			case strings.HasPrefix(a, "GHSA-"), strings.HasPrefix(a, "PYSEC-"), strings.HasPrefix(a, "MAL-"):
				as = append(as, advisoryTypes.Advisory{
					Content: advisoryContentTypes.Content{
						ID: advisoryContentTypes.AdvisoryID(a),
					},
				})
			default:
				return nil, nil, errors.Errorf("unexpected alias format. expected: %q, actual: %q", "(CVE|GHSA|PYSEC|MAL)-...", a)
			}
		}
		return as, vs, nil
	}()
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "parse aliases")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.ID),
		Advisories: append([]advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.ID),
				Description: fetched.Description,
				Severity:    severity,
				References: func() []referenceTypes.Reference {
					var rs []referenceTypes.Reference
					for r := range strings.SplitSeq(fetched.References, "\n") {
						r = strings.TrimSpace(r)
						if r == "" {
							continue
						}
						rs = append(rs, referenceTypes.Reference{
							Source: "euvd.enisa.europa.eu",
							URL:    r,
						})
					}
					return rs
				}(),
				Published: utiltime.Parse([]string{"Jan 2, 2006, 3:04:05 PM"}, fetched.DatePublished),
				Modified:  utiltime.Parse([]string{"Jan 2, 2006, 3:04:05 PM"}, fetched.DateUpdated),
			},
		}}, advisories...),
		Vulnerabilities: vulnerabilities,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.ENISAEUVDList,
			Raws: raws,
		},
	}, nil
}
