package csaf

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"slices"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/csaf"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/repository2cpe"
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

type extractor struct {
	csafDir string
	r       *utiljson.JSONReader
}

func Extract(csafDir, repository2cpeDir string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "csaf"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract RedHat CSAF")

	br := utiljson.NewJSONReader()
	var r2c repository2cpe.RepositoryToCPE
	if err := br.Read(filepath.Join(repository2cpeDir, "repository-to-cpe.json"), repository2cpeDir, &r2c); err != nil {
		return errors.Wrapf(err, "read %s", filepath.Join(repository2cpeDir, "repository-to-cpe.json"))
	}
	cpe2repository := make(map[string][]string)
	for repo, d := range r2c.Data {
		for _, cpe := range d.Cpes {
			cpe2repository[cpe] = append(cpe2repository[cpe], repo)
		}
	}

	if err := filepath.WalkDir(csafDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		e := extractor{
			csafDir: csafDir,
			r:       br.Copy(),
		}

		var adv csaf.CSAF
		if err := e.r.Read(path, e.csafDir, &adv); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		extracted, err := e.extract(adv)
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		ss, err := util.Split(string(extracted.ID), "-", ":")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(RHSA|RHBA|RHEA)-<year>:<ID>", extracted.ID)
		}

		if err := util.Write(filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", ss[0], ss[1], fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", csafDir)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.RedHatCSAF,
		Name: func() *string { t := "RedHat Enterprise Linux CSAF"; return &t }(),
		Raw: func() []repositoryTypes.Repository {
			var rs []repositoryTypes.Repository
			r1, _ := utilgit.GetDataSourceRepository(csafDir)
			if r1 != nil {
				rs = append(rs, *r1)
			}
			r2, _ := utilgit.GetDataSourceRepository(repository2cpeDir)
			if r2 != nil {
				rs = append(rs, *r2)
			}
			return rs
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

func (e extractor) extract(adv csaf.CSAF) (dataTypes.Data, error) {
	return dataTypes.Data{
		ID: dataTypes.RootID(adv.Document.Tracking.ID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:    advisoryContentTypes.AdvisoryID(adv.Document.Tracking.ID),
				Title: adv.Document.Title,
				Description: func() string {
					if i := slices.IndexFunc(adv.Document.Notes, func(e csaf.Note) bool {
						return e.Category == "general" && e.Title == "Details"
					}); i >= 0 {
						return adv.Document.Notes[i].Text
					}
					return ""
				}(),
				Severity: []severityTypes.Severity{{
					Type:   severityTypes.SeverityTypeVendor,
					Source: "https://access.redhat.com/security",
					Vendor: &adv.Document.AggregateSeverity.Text,
				}},
				References: func() []referenceTypes.Reference {
					rs := make([]referenceTypes.Reference, 0, len(adv.Document.References))
					for _, r := range adv.Document.References {
						rs = append(rs, referenceTypes.Reference{
							Source: "https://access.redhat.com/security",
							URL:    r.URL,
						})
					}
					return rs
				}(),
				Published: utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, adv.Document.Tracking.InitialReleaseDate),
				Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05-07:00"}, adv.Document.Tracking.CurrentReleaseDate),
			},
		}},
	}, nil
}
