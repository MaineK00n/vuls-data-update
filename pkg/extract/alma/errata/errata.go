package errata

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
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
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "errata"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract AlmaLinux Errata")
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

		dir, y := filepath.Split(filepath.Dir(path))
		v := filepath.Base(filepath.Clean(dir))

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var fetched errata.Erratum
		if err := json.NewDecoder(f).Decode(&fetched); err != nil {
			return errors.Wrapf(err, "decode %s", path)
		}

		published := time.Unix(int64(fetched.IssuedDate), 0)
		modified := time.Unix(int64(fetched.UpdatedDate), 0)

		info := types.Info{
			ID:          fetched.ID,
			Title:       fetched.Title,
			Description: fetched.Description,
			Severity:    fetched.Severity,
			Published:   &published,
			Modified:    &modified,
			DataSource:  source.AlmaErrata,
		}

		nvrToArches := map[string][]string{}
		modules := map[string]string{}
		for _, m := range fetched.Modules {
			modules[fmt.Sprintf("%s:%s:%s:%s:%s", m.Name, m.Stream, m.Version, m.Context, m.Arch)] = fmt.Sprintf("%s:%s", m.Name, m.Stream)
		}
		for _, p := range fetched.Packages {
			name := p.Name
			if p.Module != "" {
				m, ok := modules[p.Module]
				if !ok {
					return errors.Errorf("%s not found in modules in %s", p.Module, path)
				}
				name = fmt.Sprintf("%s::%s", m, p.Name)
			}
			vr := fmt.Sprintf("%s-%s", p.Version, p.Release)
			if p.Epoch != "" {
				vr = fmt.Sprintf("%s:%s", p.Epoch, vr)
			}
			nvrToArches[fmt.Sprintf("%s-%s", name, vr)] = append(nvrToArches[fmt.Sprintf("%s-%s", name, vr)], p.Arch)
		}

		for nvr, arches := range nvrToArches {
			ss := strings.Split(nvr, "-")
			name := strings.Join(ss[:len(ss)-2], "-")
			vr := strings.Join(ss[len(ss)-2:], "-")

			info.Affected = append(info.Affected, affectedTypes.Affected{
				Vulnerable: true,
				Package: affectedTypes.Package{
					Ecosystem: fmt.Sprintf(affectedTypes.EcosystemTypeAlma, v),
					Name:      name,
					Arches:    arches,
				},
				Ranges: []affectedTypes.Range{
					{
						Type: affectedTypes.RangeTypeEcosystem,
						Events: []affectedTypes.Event{
							{
								Introduced: "0",
							},
							{
								Fixed: vr,
							},
						},
					},
				},
			})
		}

		rm := map[string]referenceTypes.Reference{
			fmt.Sprintf("https://errata.almalinux.org/%s/%s.html", v, strings.ReplaceAll(fetched.ID, ":", "-")): {
				Name:   strings.ReplaceAll(fetched.ID, ":", "-"),
				Source: "errata.almalinux.org",
				Tags:   []referenceTypes.TagType{referenceTypes.TagVendorAdvisory},
				URL:    fmt.Sprintf("https://errata.almalinux.org/%s/%s.html", v, strings.ReplaceAll(fetched.ID, ":", "-")),
			},
		}
		for _, r := range fetched.References {
			rr, ok := rm[r.Href]
			if !ok {
				rr = referenceTypes.Reference{
					Name:   r.ID,
					Source: "errata.almalinux.org",
					URL:    r.Href,
				}
			}

			t := func() referenceTypes.TagType {
				switch r.Type {
				case "self":
					return referenceTypes.TagVendorAdvisory
				case "rhsa":
					return referenceTypes.TagThirdPartyAdvisory
				case "cve":
					return referenceTypes.TagCVE
				case "bugzilla":
					return referenceTypes.TagBugzilla
				default:
					return referenceTypes.TagMISC
				}
			}()
			if !slices.Contains(rr.Tags, t) {
				rr.Tags = append(rr.Tags, t)
			}
			rm[r.Href] = rr
		}
		info.References = maps.Values(rm)

		vm := map[string]types.Vulnerability{}
		for _, r := range rm {
			if !slices.Contains(r.Tags, referenceTypes.TagCVE) {
				continue
			}

			v, ok := vm[r.Name]
			if !ok {
				v = types.Vulnerability{
					CVE: r.Name,
				}
			}
			v.References = append(v.References, r)

			vm[r.Name] = v
		}
		info.Vulnerabilities = maps.Values(vm)

		if err := util.Write(filepath.Join(options.dir, "main", v, y, fmt.Sprintf("%s.json", info.ID)), info); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "main", v, y, fmt.Sprintf("%s.json", info.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	return nil
}
