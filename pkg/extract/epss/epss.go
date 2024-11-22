package epss

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	epssTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/epss"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/epss"
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
		dir: filepath.Join(util.CacheDir(), "extract", "epss"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Exploit Prediction Scoring System: EPSS")

	var latest time.Time
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

		t, err := time.Parse("2006-01-02", strings.TrimSuffix(filepath.Base(path), ".json"))
		if err != nil {
			return errors.Wrapf(err, "parse %s", strings.TrimSuffix(filepath.Base(path), ".json"))
		}

		if t.After(latest) {
			latest = t
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	r := utiljson.NewJSONReader()
	var fetched epss.EPSS
	if err := r.Read(filepath.Join(args, fmt.Sprintf("%d", latest.Year()), fmt.Sprintf("%s.json", latest.Format("2006-01-02"))), args, &fetched); err != nil {
		return errors.Wrapf(err, "read json %s", filepath.Join(args, fmt.Sprintf("%d", latest.Year()), fmt.Sprintf("%s.json", latest.Format("2006-01-02"))))
	}

	for _, d := range fetched.Data {
		splitted, err := util.Split(d.ID, "-", "-")
		if err != nil {
			return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", d.ID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", d.ID)
		}

		data := dataTypes.Data{
			ID: dataTypes.RootID(d.ID),
			Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(d.ID),
					EPSS: &epssTypes.EPSS{
						Model:      fetched.Model,
						ScoreDate:  latest,
						EPSS:       d.EPSS,
						Percentile: d.Percentile,
					},
					References: []referenceTypes.Reference{{
						Source: "api.first.org",
						URL:    fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", d.ID),
					}},
				},
			}},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.EPSS,
				Raws: r.Paths(),
			},
		}

		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", d.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", d.ID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.EPSS,
		Name: func() *string { t := "EPSS: Exploit Prediction Scoring System"; return &t }(),
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
