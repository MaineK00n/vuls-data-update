package kev

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
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	kevTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev"
	enisaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/enisa"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/extract/util/filepath"
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
	seen := make(map[string]string) // EUVD ID -> CVE ID
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
		var fetched kev.Vulnerability
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		if fix, ok := euvdIDFixes[fetched.CVEID]; ok {
			if fetched.EUVDID != fix.wrong {
				return errors.Errorf("unexpected EUVD ID of %s. expected: %q, actual: %q; the EUVD ID fix is stale", fetched.CVEID, fix.wrong, fetched.EUVDID)
			}
			fetched.EUVDID = fix.correct
		}

		splitted, err := util.Split(fetched.EUVDID, "-", "-")
		if err != nil {
			return errors.Errorf("unexpected EUVD ID format. expected: %q, actual: %q", "EUVD-yyyy-\\d{4,}", fetched.EUVDID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Errorf("unexpected EUVD ID format. expected: %q, actual: %q", "EUVD-yyyy-\\d{4,}", fetched.EUVDID)
		}

		// One file is written per EUVD ID, so an EUVD ID shared by several CVEs
		// would silently keep only one of them.
		if cveID, ok := seen[fetched.EUVDID]; ok {
			return errors.Errorf("unexpected duplicate EUVD ID. %s is assigned to both %s and %s", fetched.EUVDID, cveID, fetched.CVEID)
		}
		seen[fetched.EUVDID] = fetched.CVEID

		extracted, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		p, err := utilfilepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", extracted.ID))
		if err != nil {
			return errors.Wrap(err, "join")
		}

		if err := util.Write(p, extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", p)
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

type euvdIDFix struct {
	wrong   string
	correct string
}

// euvdIDFixes corrects EUVD IDs that upstream eukev.json assigns to the wrong
// CVE, keyed by CVE ID. An entry whose CVE carries any EUVD ID other than the
// wrong one is an error, so that a fix is removed once upstream is corrected
// and an unexpected upstream change is not silently passed through.
var euvdIDFixes = map[string]euvdIDFix{
	// EUVD-2026-56431 belongs to CVE-2026-65660, but upstream also assigns it
	// to these CVEs: https://github.com/enisaeu/CNW/issues/66
	"CVE-2026-88771": {wrong: "EUVD-2026-56431", correct: "EUVD-2026-87958"},
	"CVE-2026-88772": {wrong: "EUVD-2026-56431", correct: "EUVD-2026-87959"},
}

func sanitize(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func extract(fetched kev.Vulnerability, raws []string) (dataTypes.Data, error) {
	dateReported := utiltime.Parse([]string{"2006/01/02"}, fetched.DateReported)
	if dateReported == nil {
		return dataTypes.Data{}, errors.Errorf("unexpected dateReported format. expected: %q, actual: %q", "2006/01/02", fetched.DateReported)
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.EUVDID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID: advisoryContentTypes.AdvisoryID(fetched.EUVDID),
				KEV: &kevTypes.KEV{
					VendorProject: fetched.VendorProject,
					Product:       fetched.Product,
					Notes:         sanitize(fetched.Notes),
					ENISA: &enisaTypes.ENISA{
						DateReported: *dateReported,
						PatchedSince: sanitize(fetched.PatchedSince),
						OriginSource: sanitize(fetched.OriginSource),
						// The deprecated fields stay filled for consumers that have not moved to the slices yet.
						ExploitationType:       strings.Join(fetched.ExploitationType, ", "),       //nolint:staticcheck // SA1019: intentionally kept filled
						ThreatActorsExploiting: strings.Join(fetched.ThreatActorsExploiting, ", "), //nolint:staticcheck // SA1019: intentionally kept filled
						ExploitationTypes:      fetched.ExploitationType,
						ThreatActors:           fetched.ThreatActorsExploiting,
					},
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
						if len(fetched.CWEs) == 0 {
							return nil
						}
						return []cweTypes.CWE{{
							Source: "enisa.europa.eu/kev",
							CWE:    fetched.CWEs,
						}}
					}(),
				},
			}}
		}(),
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.ENISAKEV,
			Raws: raws,
		},
	}, nil
}
