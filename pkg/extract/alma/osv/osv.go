package osv

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/affected"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
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

		published, err := time.Parse("2006-01-02T15:04:05Z", fetched.Published)
		if err != nil {
			return errors.Wrapf(err, "parse %s in %s", fetched.Published, fpath)
		}
		modified, err := time.Parse("2006-01-02T15:04:05Z", fetched.Modified)
		if err != nil {
			return errors.Wrapf(err, "parse %s in %s", fetched.Modified, fpath)
		}

		info := types.Info{
			ID:          fetched.ID,
			Title:       fetched.Summary,
			Description: fetched.Details,
			Published:   &published,
			Modified:    &modified,
			DataSource:  source.AlmaOSV,
		}

		var as []affectedTypes.Affected
		for _, a := range fetched.Affected {
			p, err := func() (affectedTypes.Package, error) {
				lhs, rhs, ok := strings.Cut(a.Package.Ecosystem, ":")
				if !ok || lhs != "AlmaLinux" {
					return affectedTypes.Package{}, errors.Errorf("unexpected ecosystem format. expected: %q, actual: %q", "AlmaLinux:<version>", a.Package.Ecosystem)
				}
				return affectedTypes.Package{
					Ecosystem: fmt.Sprintf(affectedTypes.EcosystemTypeAlma, rhs),
					Name:      a.Package.Name,
				}, nil
			}()
			if err != nil {
				return errors.Wrapf(err, "parse package: %v in %s", a.Package, fpath)
			}
			var rs []affectedTypes.Range
			for _, r := range a.Ranges {
				if r.Type != affectedTypes.RangeTypeEcosystem.String() {
					return errors.Errorf("unexpected range type. expected: %q, actual: %q", affectedTypes.RangeTypeEcosystem, r.Type)
				}
				var es []affectedTypes.Event
				for _, e := range r.Events {
					es = append(es, e)
				}

				rs = append(rs, affectedTypes.Range{
					Type:   affectedTypes.RangeTypeEcosystem,
					Events: es,
				})
			}

			as = append(as, affectedTypes.Affected{
				Vulnerable: true,
				Package:    p,
				Ranges:     rs,
			})
		}
		info.Affected = as

		rm := map[string]referenceTypes.Reference{}
		for _, r := range fetched.References {
			u, err := url.Parse(r.URL)
			if err != nil {
				return errors.Wrapf(err, "parse %s in %s", r.URL, fpath)
			}

			rr, ok := rm[r.URL]
			if !ok {
				rr = referenceTypes.Reference{
					Name:   path.Base(u.Path),
					Source: "errata.almalinux.org",
					URL:    r.URL,
				}
				if u.Host == "errata.almalinux.org" {
					rr.Name = strings.TrimSuffix(path.Base(u.Path), ".html")
				}
			}

			t := func() referenceTypes.TagType {
				switch u.Host {
				case "errata.almalinux.org":
					return referenceTypes.TagVendorAdvisory
				case "access.redhat.com":
					switch r.Type {
					case "ADVISORY":
						return referenceTypes.TagThirdPartyAdvisory
					default:
						if !strings.HasPrefix(path.Base(u.Path), "CVE-") {
							return referenceTypes.TagMISC
						}
						return referenceTypes.TagCVE
					}
				case "bugzilla.redhat.com":
					return referenceTypes.TagBugzilla
				case "vulners.com":
					return referenceTypes.TagCVE
				default:
					return referenceTypes.TagMISC
				}
			}()
			if !slices.Contains(rr.Tags, t) {
				rr.Tags = append(rr.Tags, t)
			}
			rm[r.URL] = rr
		}
		info.References = maps.Values(rm)

		vm := map[string]types.Vulnerability{}
		for _, related := range fetched.Related {
			if !strings.HasPrefix(related, "CVE-") {
				continue
			}

			vm[related] = types.Vulnerability{
				CVE: related,
			}
		}
		for _, r := range rm {
			if !slices.Contains(r.Tags, referenceTypes.TagCVE) {
				continue
			}
			v, ok := vm[r.Name]
			if !ok {
				continue
			}
			v.References = append(v.References, r)

			vm[r.Name] = v
		}
		info.Vulnerabilities = maps.Values(vm)

		if err := util.Write(filepath.Join(options.dir, "main", filepath.Base(filepath.Dir(fpath)), fmt.Sprintf("%s.json", info.ID)), info); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "main", filepath.Base(filepath.Dir(fpath)), fmt.Sprintf("%s.json", info.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}
