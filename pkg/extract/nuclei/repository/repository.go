package repository

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	exploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/exploit"
	nucleiTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/exploit/nuclei"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	fetchTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nuclei/repository"
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
		dir: filepath.Join(util.CacheDir(), "extract", "nuclei", "repository"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Nuclei Templates Repository")

	cveExploits, err := extract(args)
	if err != nil {
		return errors.Wrap(err, "extract")
	}

	for cveID, data := range cveExploits {
		splitted, err := util.Split(cveID, "-", "-")
		if err != nil {
			return errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cveID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cveID)
		}
		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", cveID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", cveID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.NucleiRepository,
		Name: new("Nuclei Templates Repository"),
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

func normalizeCVEID(s string) string {
	upper := strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(upper, "CVE-") {
		return ""
	}
	return upper
}

func collectCVEIDs(v *any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	var out []string
	switch val := (*v).(type) {
	case nil:
		return nil, nil
	case string:
		if id := normalizeCVEID(val); id != "" {
			out = append(out, id)
		}
	case []any:
		for _, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, errors.Errorf("unexpected cve-id element type. expected: %q, actual: %T", "string", item)
			}
			if id := normalizeCVEID(s); id != "" {
				out = append(out, id)
			}
		}
	default:
		return nil, errors.Errorf("unexpected cve-id type. expected: %q, actual: %T", []string{"string", "[]any"}, *v)
	}
	return out, nil
}

func extract(args string) (map[string]dataTypes.Data, error) {
	cveExploits := make(map[string]dataTypes.Data)

	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var f fetchTypes.Template
		if err := r.Read(path, args, &f); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		if f.Info.Classification == nil {
			return nil
		}

		cveIDs, err := collectCVEIDs(f.Info.Classification.CVEID)
		if err != nil {
			return errors.Wrapf(err, "collect cve-id from %s", path)
		}
		if len(cveIDs) == 0 {
			return nil
		}

		rel, err := filepath.Rel(args, path)
		if err != nil {
			return errors.Wrapf(err, "get relative path of %s from %s", path, args)
		}

		exploit := exploitTypes.Exploit{
			Source: "nuclei.projectdiscovery.io",
			Link:   fmt.Sprintf("https://github.com/projectdiscovery/nuclei-templates/blob/main/%s.yaml", strings.TrimSuffix(filepath.ToSlash(rel), ".json")),
			Description: func() string {
				if f.Info.Description == nil {
					return ""
				}
				return strings.TrimSpace(*f.Info.Description)
			}(),
			Nuclei: &nucleiTypes.Nuclei{
				TemplateID: f.ID,
				Verified: func() bool {
					if f.Info.Metadata == nil {
						return false
					}
					switch v := (*f.Info.Metadata)["verified"].(type) {
					case bool:
						return v
					case string:
						b, _ := strconv.ParseBool(v)
						return b
					default:
						return false
					}
				}(),
			},
		}

		for _, cveID := range cveIDs {
			base, ok := cveExploits[cveID]
			if !ok {
				base = dataTypes.Data{
					ID: dataTypes.RootID(cveID),
					Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID(cveID),
						},
					}},
					DataSource: sourceTypes.Source{
						ID: sourceTypes.NucleiRepository,
					},
				}
			}
			base.Vulnerabilities[0].Content.Exploit = append(base.Vulnerabilities[0].Content.Exploit, exploit)
			base.DataSource.Raws = append(base.DataSource.Raws, r.Paths()...)
			cveExploits[cveID] = base
		}

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", args)
	}

	return cveExploits, nil
}
