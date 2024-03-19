package osv

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	apk "github.com/knqyf263/go-apk-version"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity"
	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v2"
	v30 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v30"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v31"
	v40 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/severity/cvss/v40"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	utilversion "github.com/MaineK00n/vuls-data-update/pkg/extract/util/version"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/osv"
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
		dir: filepath.Join(util.CacheDir(), "extract", "alpine", "osv"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract Alpine Linux OSV")
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

		var fetched osv.OSV
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		extracted, err := extract(fetched)
		if err != nil {
			return errors.Wrapf(err, "extract for %s", fetched.ID)
		}

		if err := util.Write(filepath.Join(options.dir, filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)), extracted); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}

func extract(fetched osv.OSV) (types.Data, error) {
	extracted := types.Data{
		ID: fetched.ID,
		Vulnerabilities: []types.Vulnerability{{
			ID:          fetched.ID,
			Title:       fetched.Summary,
			Description: fetched.Details,
			References: []reference.Reference{{
				Source: "security.alpinelinux.org",
				URL:    fmt.Sprintf("https://security.alpinelinux.org/vuln/%s", fetched.ID),
			}},
			Published: utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Published),
			Modified:  utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Modified),
		}},
		DataSource: source.AlpineOSV,
	}

	for _, r := range fetched.References {
		extracted.Vulnerabilities[0].References = append(extracted.Vulnerabilities[0].References, reference.Reference{
			Source: "security.alpinelinux.org",
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
			extracted.Vulnerabilities[0].Severity = append(extracted.Vulnerabilities[0].Severity, severityTypes.Severity{
				Type:   severityTypes.SeverityTypeCVSSv2,
				Source: "security.alpinelinux.org",
				CVSSv2: cvss,
			})
		case "CVSS_V3":
			switch {
			case strings.HasPrefix(s.Score, "CVSS:3.0"):
				cvss, err := v30.Parse(s.Score)
				if err != nil {
					return types.Data{}, errors.Wrapf(err, "parse cvss v3.0 vector: %s", s.Score)
				}
				extracted.Vulnerabilities[0].Severity = append(extracted.Vulnerabilities[0].Severity, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv30,
					Source:  "security.alpinelinux.org",
					CVSSv30: cvss,
				})
			case strings.HasPrefix(s.Score, "CVSS:3.1"):
				cvss, err := v31.Parse(s.Score)
				if err != nil {
					return types.Data{}, errors.Wrapf(err, "parse cvss v3.1 vector: %s", s.Score)
				}
				extracted.Vulnerabilities[0].Severity = append(extracted.Vulnerabilities[0].Severity, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv31,
					Source:  "security.alpinelinux.org",
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
				extracted.Vulnerabilities[0].Severity = append(extracted.Vulnerabilities[0].Severity, severityTypes.Severity{
					Type:    severityTypes.SeverityTypeCVSSv40,
					Source:  "security.alpinelinux.org",
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
		if !strings.HasPrefix(a.Package.Ecosystem, "Alpine:v") {
			continue
		}

		d := detection.Detection{
			Ecosystem:  fmt.Sprintf(detection.EcosystemTypeAlpine, strings.TrimPrefix(a.Package.Ecosystem, "Alpine:v")),
			Vulnerable: true,
			Package: detection.Package{
				Name: a.Package.Name,
			},
		}
		var affected *detection.Affected
		for _, r := range a.Ranges {
			vget := func(e osv.Event) string {
				if e.Introduced != "" {
					return e.Introduced
				}
				if e.Fixed != "" {
					return e.Fixed
				}
				if e.LastAffected != "" {
					return e.LastAffected
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
				affected = &detection.Affected{
					Type: detection.RangeTypeAPK,
				}

				slices.SortFunc(r.Events, func(i, j osv.Event) int {
					v1, _ := apk.NewVersion(vget(i))
					v2, _ := apk.NewVersion(vget(j))
					return v1.Compare(v2)
				})

				var i int
				for _, e := range r.Events {
					switch {
					case e.Introduced != "":
						affected.Range = append(affected.Range, detection.Range{
							GreaterEqual: func() string {
								if e.Introduced == "0" {
									return ""
								}
								return e.Introduced
							}(),
						})
						i = len(affected.Range) - 1
					case e.Fixed != "":
						affected.Range[i].LessThan = e.Fixed
						affected.Fixed = append(affected.Fixed, e.Fixed)
					case e.LastAffected != "":
						affected.Range[i].LessEqual = e.LastAffected
					case e.Limit != "":
					default:
						return types.Data{}, errors.New("no event is set")
					}
				}

				d.Affected = affected
			default:
				return types.Data{}, errors.Errorf("%s is not supported", r.Type)
			}
		}

		var vs []detection.Range
		for _, v := range a.Versions {
			if d.Affected == nil || !utilversion.Contains(*d.Affected, v) {
				vs = append(vs, detection.Range{Equal: v})
			}
		}
		if len(vs) > 0 {
			if d.Affected == nil {
				d.Affected = &detection.Affected{Type: detection.RangeTypeAPK}
			}
			d.Affected.Range = append(d.Affected.Range, vs...)
		}

		extracted.Detection = append(extracted.Detection, d)
	}

	return extracted, nil
}
