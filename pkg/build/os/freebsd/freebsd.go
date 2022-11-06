package freebsd

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/freebsd"
)

type options struct {
	srcDir        string
	destVulnDir   string
	destDetectDir string
}

type Option interface {
	apply(*options)
}

type srcDirOption string

func (d srcDirOption) apply(opts *options) {
	opts.srcDir = string(d)
}

func WithSrcDir(dir string) Option {
	return srcDirOption(dir)
}

type destVulnDirOption string

func (d destVulnDirOption) apply(opts *options) {
	opts.destVulnDir = string(d)
}

func WithDestVulnDir(dir string) Option {
	return destVulnDirOption(dir)
}

type destDetectDirOption string

func (d destDetectDirOption) apply(opts *options) {
	opts.destDetectDir = string(d)
}

func WithDestDetectDir(dir string) Option {
	return destDetectDirOption(dir)
}

func Build(opts ...Option) error {
	options := &options{
		srcDir:        filepath.Join(util.SourceDir(), "freebsd"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "freebsd"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build FreeBSD")
	if err := os.RemoveAll(options.destDetectDir); err != nil {
		return errors.Wrapf(err, "remove %s", options.destDetectDir)
	}
	if err := filepath.WalkDir(options.srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		sf, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer sf.Close()

		var sv freebsd.Advisory
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		if sv.Cancelled != nil {
			return nil
		}

		var ids []string
		for _, r := range sv.References {
			if r.Source != "CVE" {
				continue
			}
			ids = append(ids, r.Text)
		}
		if len(ids) == 0 {
			ids = append(ids, sv.Vid)
		}

		for _, id := range ids {
			if err := func() error {
				y := "others"
				if strings.HasPrefix(id, "CVE-") {
					y = strings.Split(id, "-")[1]
					if _, err := strconv.Atoi(y); err != nil {
						return nil
					}
				}
				if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
				}
				if err := os.MkdirAll(filepath.Join(options.destDetectDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, y))
				}

				dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)))
				}
				defer dvf.Close()

				var dv build.Vulnerability
				if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillVulnerability(&dv, &sv, id)

				if err := dvf.Truncate(0); err != nil {
					return errors.Wrap(err, "truncate file")
				}
				if _, err := dvf.Seek(0, 0); err != nil {
					return errors.Wrap(err, "set offset")
				}
				enc := json.NewEncoder(dvf)
				enc.SetIndent("", "  ")
				if err := enc.Encode(dv); err != nil {
					return errors.Wrap(err, "encode json")
				}

				ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", id)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", id)))
				}
				defer ddf.Close()

				var dd build.DetectPackage
				if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillDetect(&dd, id, &sv)

				if err := ddf.Truncate(0); err != nil {
					return errors.Wrap(err, "truncate file")
				}
				if _, err := ddf.Seek(0, 0); err != nil {
					return errors.Wrap(err, "set offset")
				}
				enc = json.NewEncoder(ddf)
				enc.SetIndent("", "  ")
				if err := enc.Encode(dd); err != nil {
					return errors.Wrap(err, "encode json")
				}

				return nil
			}(); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk freebsd")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *freebsd.Advisory, id string) {
	if dv.ID == "" {
		dv.ID = id
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.FreeBSD = append(dv.Advisory.Arch, build.Advisory{
		ID:  sv.Vid,
		URL: fmt.Sprintf("https://www.vuxml.org/freebsd/%s.html", sv.Vid),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.FreeBSD == nil {
		dv.Title.FreeBSD = map[string]string{}
	}
	dv.Title.FreeBSD[sv.Vid] = sv.Topic

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.FreeBSD == nil {
		dv.Description.FreeBSD = map[string]string{}
	}
	dv.Description.FreeBSD[sv.Vid] = sv.Description

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.FreeBSD == nil {
		dv.Published.FreeBSD = map[string]*time.Time{}
	}
	dv.Published.FreeBSD[sv.Vid] = sv.Dates.Discovery

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if dv.Modified.FreeBSD == nil {
		dv.Modified.FreeBSD = map[string]*time.Time{}
	}
	dv.Modified.FreeBSD[sv.Vid] = sv.Dates.Entry

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.FreeBSD == nil {
		dv.References.FreeBSD = map[string][]build.Reference{}
	}
	for _, r := range sv.References {
		switch lhs, _, _ := strings.Cut(r.Source, ":"); lhs {
		case "CVE":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: r.Source,
				Name:   r.Text,
				URL:    fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", r.Text),
			})
		case "FreebsdSA":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: r.Source,
				Name:   r.Text,
				URL:    fmt.Sprintf("https://www.freebsd.org/security/advisories/FreeBSD-%s.asc", r.Text),
			})
		case "FreebsdPR":
			var u string
			_, rhs, found := strings.Cut(r.Text, "/")
			if found {
				u = fmt.Sprintf("https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=%s", rhs)
			}
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: "BUG",
				Name:   r.Text,
				URL:    u,
			})
		case "MLIST":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: "MLIST",
				Name:   r.Source,
				URL:    r.Text,
			})
		case "BID":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: r.Source,
				Name:   r.Text,
				URL:    fmt.Sprintf("http://www.securityfocus.com/bid/%s", r.Text),
			})
		case "CertSA":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: r.Source,
				Name:   r.Text,
				URL:    fmt.Sprintf("http://www.cert.org/advisories/%s.html", r.Text),
			})
		case "CertVU":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: r.Source,
				Name:   r.Text,
				URL:    fmt.Sprintf("http://www.kb.cert.org/vuls/id/%s", r.Text),
			})
		case "USCertSA":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: r.Source,
				Name:   r.Text,
			})
		case "USCertTA":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: r.Source,
				Name:   r.Text,
				URL:    fmt.Sprintf("http://www.us-cert.gov/cas/techalerts/%s.html", r.Text),
			})
		case "URL":
			dv.References.FreeBSD[sv.Vid] = append(dv.References.FreeBSD[sv.Vid], build.Reference{
				Source: "MISC",
				Name:   r.Text,
				URL:    r.Text,
			})
		}
	}
}

func fillDetect(dd *build.DetectPackage, id string, sv *freebsd.Advisory) {
	if dd.ID == "" {
		dd.ID = id
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for _, p := range sv.Affects {
		vss := make([][]build.Version, 0, len(p.Range))
		for _, a := range p.Range {
			var vs []build.Version
			if a.Eq != "" {
				vs = append(vs, build.Version{
					Operator: "eq",
					Version:  a.Eq,
				})
			}
			if a.Ge != "" {
				vs = append(vs, build.Version{
					Operator: "ge",
					Version:  a.Ge,
				})
			}
			if a.Gt != "" {
				vs = append(vs, build.Version{
					Operator: "gt",
					Version:  a.Gt,
				})
			}
			if a.Le != "" {
				vs = append(vs, build.Version{
					Operator: "le",
					Version:  a.Le,
				})
			}
			if a.Lt != "" {
				vs = append(vs, build.Version{
					Operator: "lt",
					Version:  a.Lt,
				})
			}
			vss = append(vss, vs)
		}

		dd.Packages[sv.Vid] = append(dd.Packages[sv.Vid], build.Package{
			Name:    p.Name,
			Status:  "fixed",
			Version: vss,
		})
	}
}
