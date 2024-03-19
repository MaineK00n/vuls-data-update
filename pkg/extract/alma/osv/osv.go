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

	rpm "github.com/knqyf263/go-rpm-version"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	utilversion "github.com/MaineK00n/vuls-data-update/pkg/extract/util/version"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/osv"
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
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "osv"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract AlmaLinux OSV")
	if err := filepath.WalkDir(args, func(fpath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if filepath.Ext(fpath) != ".json" {
			return nil
		}

		if !strings.HasPrefix(filepath.Base(fpath), "ALSA-") {
			return nil
		}

		f, err := os.Open(fpath)
		if err != nil {
			return errors.Wrapf(err, "open %s", fpath)
		}
		defer f.Close()

		var fetched osv.OSV
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", fpath)
		}

		extracted, err := extract(fetched)
		if err != nil {
			return errors.Wrapf(err, "extract for %s", fetched.ID)
		}

		if err := util.Write(filepath.Join(options.dir, filepath.Base(filepath.Dir(fpath)), fmt.Sprintf("%s.json", extracted.ID)), extracted); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, filepath.Base(filepath.Dir(fpath)), fmt.Sprintf("%s.json", extracted.ID)))
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
		Advisories: []types.Advisory{{
			ID:          fetched.ID,
			Title:       fetched.Summary,
			Description: fetched.Details,
			Published:   utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Published),
			Modified:    utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.Modified),
		}},
		DataSource: source.AlmaOSV,
	}

	for _, r := range fetched.References {
		extracted.Advisories[0].References = append(extracted.Advisories[0].References, reference.Reference{
			Source: "errata.almalinux.org",
			URL:    r.URL,
		})
	}

	for _, related := range fetched.Related {
		if !strings.HasPrefix(related, "CVE-") {
			continue
		}
		extracted.Vulnerabilities = append(extracted.Vulnerabilities, types.Vulnerability{
			ID: related,
		})
	}

	for _, a := range fetched.Affected {
		if !strings.HasPrefix(a.Package.Ecosystem, "AlmaLinux:") {
			continue
		}

		d := detection.Detection{
			Ecosystem:  fmt.Sprintf(detection.EcosystemTypeAlma, strings.TrimPrefix(a.Package.Ecosystem, "AlmaLinux:")),
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
					Type: detection.RangeTypeRPM,
				}

				slices.SortFunc(r.Events, func(i, j osv.Event) int {
					return rpm.NewVersion(vget(i)).Compare(rpm.NewVersion(vget(j)))
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
				d.Affected = &detection.Affected{Type: detection.RangeTypeRPM}
			}
			d.Affected.Range = append(d.Affected.Range, vs...)
		}

		extracted.Detection = append(extracted.Detection, d)
	}

	return extracted, nil
}
