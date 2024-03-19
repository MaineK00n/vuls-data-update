package ghsa

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v2"
	v30 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v30"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v31"
	v40 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v40"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	utilversion "github.com/MaineK00n/vuls-data-update/pkg/extract/util/version"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cargo/ghsa"
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
		dir: filepath.Join(util.CacheDir(), "extract", "cargo", "ghsa"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract GitHub Security Advisory: Cargo")
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

		var fetched ghsa.GHSA
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		extracted, err := extract(fetched)
		if err != nil {
			return errors.Wrapf(err, "extract for %s", fetched.ID)
		}

		dir, m := filepath.Split(filepath.Dir(filepath.Dir(path)))
		if err := util.Write(filepath.Join(options.dir, filepath.Base(filepath.Dir(dir)), m, extracted.ID, fmt.Sprintf("%s.json", extracted.ID)), extracted); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, filepath.Base(filepath.Dir(dir)), m, extracted.ID, fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}

func extract(fetched ghsa.GHSA) (types.Data, error) {
	extracted := types.Data{
		ID: fetched.ID,
		Advisories: []types.Advisory{{
			ID:          fetched.ID,
			Title:       fetched.Summary,
			Description: fetched.Details,
			Published:   utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Published),
			Modified:    utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Modified),
		}},
		DataSource: source.CargoGHSA,
	}

	for _, a := range fetched.Aliases {
		extracted.Vulnerabilities = append(extracted.Vulnerabilities, types.Vulnerability{
			ID: a,
		})
	}

	for _, r := range fetched.References {
		extracted.Advisories[0].References = append(extracted.Advisories[0].References, reference.Reference{
			Source: "github.com/advisories",
			URL:    r.URL,
		})
	}

	for _, s := range fetched.Severity {
		switch s.Type {
		case "CVSS_V2":
			cvss, err := v2.Parse(s.Score)
			if err != nil {
				return types.Data{}, errors.Wrapf(err, "parse cvss v2 vector: %s", s.Score)
			}
			extracted.Advisories[0].Severity = append(extracted.Advisories[0].Severity, severity.Severity{
				Type:   severity.SeverityTypeCVSSv2,
				Source: "github.com/advisories",
				CVSSv2: cvss,
			})
		case "CVSS_V3":
			switch {
			case strings.HasPrefix(s.Score, "CVSS:3.0"):
				cvss, err := v30.Parse(s.Score)
				if err != nil {
					return types.Data{}, errors.Wrapf(err, "parse cvss v3.0 vector: %s", s.Score)
				}
				extracted.Advisories[0].Severity = append(extracted.Advisories[0].Severity, severity.Severity{
					Type:    severity.SeverityTypeCVSSv30,
					Source:  "github.com/advisories",
					CVSSv30: cvss,
				})
			case strings.HasPrefix(s.Score, "CVSS:3.1"):
				cvss, err := v31.Parse(s.Score)
				if err != nil {
					return types.Data{}, errors.Wrapf(err, "parse cvss v3.1 vector: %s", s.Score)
				}
				extracted.Advisories[0].Severity = append(extracted.Advisories[0].Severity, severity.Severity{
					Type:    severity.SeverityTypeCVSSv31,
					Source:  "github.com/advisories",
					CVSSv31: cvss,
				})
			default:
				return types.Data{}, errors.Errorf("unexpected cvss v3 vector: %s", s.Score)
			}
		case "CVSS_V4":
			switch {
			case strings.HasPrefix(s.Score, "CVSS:4.0"):
				cvss, err := v40.Parse(s.Score)
				if err != nil {
					return types.Data{}, errors.Wrapf(err, "parse cvss v4.0 vector: %s", s.Score)
				}
				extracted.Advisories[0].Severity = append(extracted.Advisories[0].Severity, severity.Severity{
					Type:    severity.SeverityTypeCVSSv40,
					Source:  "github.com/advisories",
					CVSSv40: cvss,
				})
			default:
				return types.Data{}, errors.Errorf("unexpected cvss v4 vector: %s", s.Score)
			}
		default:
			return types.Data{}, errors.Errorf("unexpected severity type: %s", s.Type)
		}
	}

	for _, a := range fetched.Affected {
		if a.Package.Ecosystem != "crates.io" {
			continue
		}

		d := detection.Detection{
			Ecosystem:  detection.EcosystemTypeCargo,
			Vulnerable: true,
			Package: detection.Package{
				Name: a.Package.Name,
			},
		}

		if m, ok := a.EcosystemSpecific.(map[string]interface{}); ok {
			for k, v := range m {
				switch k {
				case "affected_functions":
					if fs, ok := v.([]string); ok {
						d.Package.Functions = fs
					}
				default:
					log.Printf("[WARN] ecosystem_specific new item: %s", k)
				}
			}
		}

		if m, ok := a.DatabaseSpecific.(map[string]interface{}); ok {
			for k, v := range m {
				switch k {
				case "last_known_affected_version_range":
					s, ok := v.(string)
					if !ok {
						return types.Data{}, errors.Errorf("unexpected last_known_affected_version_range format. expected: %q, actual: %q", "<operator> <affected version>", v)
					}
					op, v, ok := strings.Cut(s, " ")
					if !ok {
						return types.Data{}, errors.Errorf("unexpected last_known_affected_version_range format. expected: %q, actual: %q", "<operator> <affected version>", s)
					}
					switch op {
					case "<", "<=":
						for i := range a.Ranges {
							a.Ranges[i].Events = append(a.Ranges[i].Events, ghsa.Event{LastAffected: s})
						}
					case ">", ">=":
						for i := range a.Ranges {
							a.Ranges[i].Events = append(a.Ranges[i].Events, ghsa.Event{Introduced: s})
						}
					case "=":
						a.Versions = append(a.Versions, v)
					default:
						return types.Data{}, errors.Errorf("unexpected operator. op: %q", op)
					}
				case "source":
				default:
					log.Printf("[WARN] database_specific new item: %s", k)
				}
			}
		}

		var affected *detection.Affected
		for _, r := range a.Ranges {
			vget := func(e ghsa.Event) string {
				if e.Introduced != "" {
					_, v, ok := strings.Cut(e.Introduced, " ")
					if !ok {
						return e.Introduced
					}
					return v
				}
				if e.Fixed != "" {
					return e.Fixed
				}
				if e.LastAffected != "" {
					_, v, ok := strings.Cut(e.LastAffected, " ")
					if !ok {
						return e.LastAffected
					}
					return v
				}
				if e.Limit != "" {
					return e.Limit
				}
				return ""
			}

			switch r.Type {
			case "SEMVER", "GIT":
				continue
			case "ECOSYSTEM":
				if affected == nil {
					affected = &detection.Affected{
						Type: detection.RangeTypeSEMVER,
					}
				}

				slices.SortFunc(r.Events, func(i, j ghsa.Event) int {
					v1, _ := version.NewSemver(vget(i))
					v2, _ := version.NewSemver(vget(j))
					return v1.Compare(v2)
				})

				var i *int
				for _, e := range r.Events {
					switch {
					case e.Introduced != "":
						switch op, v, _ := strings.Cut(e.Introduced, " "); op {
						case ">":
							affected.Range = append(affected.Range, detection.Range{
								GreaterThan: func() string {
									if v == "0" {
										return ""
									}
									return v
								}(),
							})
							i = func() *int { i := len(affected.Range) - 1; return &i }()
						case ">=":
							affected.Range = append(affected.Range, detection.Range{
								GreaterEqual: func() string {
									if v == "0" {
										return ""
									}
									return v
								}(),
							})
							i = func() *int { i := len(affected.Range) - 1; return &i }()
						default:
							affected.Range = append(affected.Range, detection.Range{
								GreaterEqual: func() string {
									if e.Introduced == "0" {
										return ""
									}
									return e.Introduced
								}(),
							})
							i = func() *int { i := len(affected.Range) - 1; return &i }()
						}
					case e.Fixed != "":
						if i == nil {
							return types.Data{}, errors.New("introduced object for fixed object not found")
						}
						affected.Range[*i].LessThan = e.Fixed
						affected.Range[*i].LessEqual = ""
						affected.Fixed = append(affected.Fixed, e.Fixed)
						i = nil
					case e.LastAffected != "":
						switch op, v, _ := strings.Cut(e.LastAffected, " "); op {
						case "<":
							if i == nil {
								break
							}
							affected.Range[*i].LessThan = v
						case "<=":
							affected.Range[*i].LessEqual = v
						default:
							if i == nil {
								return types.Data{}, errors.New("introduced object for last_affected object not found")
							}
							affected.Range[*i].LessEqual = e.LastAffected
						}
					case e.Limit != "":
					default:
						return types.Data{}, errors.New("no event is set")
					}
				}
			default:
				return types.Data{}, errors.Errorf("%s is not supported", r.Type)
			}
		}

		var vs []detection.Range
		for _, v := range a.Versions {
			if affected == nil || !utilversion.Contains(*affected, v) {
				vs = append(vs, detection.Range{Equal: v})
			}
		}
		if len(vs) > 0 {
			if affected == nil {
				affected = &detection.Affected{Type: detection.RangeTypeSEMVER}
			}
			affected.Range = append(affected.Range, vs...)
		}

		d.Affected = affected
		extracted.Detection = append(extracted.Detection, d)
	}

	if m, ok := fetched.DatabaseSpecific.(map[string]interface{}); ok {
		for k, v := range m {
			switch k {
			case "cwe_ids":
				if cwes, ok := v.([]string); ok {
					extracted.Advisories[0].CWE = append(extracted.Advisories[0].CWE, cwe.CWE{
						Source: "github.com/advisories",
						CWE:    cwes,
					})
				}
			case "github_reviewed":
				extracted.Advisories[0].Optional = map[string]interface{}{k: v}
			case "github_reviewed_at":
			case "nvd_published_at":
			case "severity":
				if s, ok := v.(string); ok {
					extracted.Advisories[0].Severity = append(extracted.Advisories[0].Severity, severity.Severity{
						Type:   severity.SeverityTypeVendor,
						Source: "github.com/advisories",
						Vendor: &s,
					})
				}
			default:
				log.Printf("[WARN] database_specific new item: %s", k)
			}
		}
	}

	return extracted, nil
}
