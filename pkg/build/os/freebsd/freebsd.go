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
	srcDir             string
	srcCompressFormat  string
	destVulnDir        string
	destDetectDir      string
	destCompressFormat string
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

type srcCompressFormatOption string

func (d srcCompressFormatOption) apply(opts *options) {
	opts.srcCompressFormat = string(d)
}

func WithSrcCompressFormat(compress string) Option {
	return srcCompressFormatOption(compress)
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

type destCompressFormatOption string

func (d destCompressFormatOption) apply(opts *options) {
	opts.destCompressFormat = string(d)
}

func WithDestCompressFormat(compress string) Option {
	return destCompressFormatOption(compress)
}

func Build(opts ...Option) error {
	options := &options{
		srcDir:             filepath.Join(util.SourceDir(), "freebsd"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "freebsd"),
		destCompressFormat: "",
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

		sbs, err := util.Open(path, options.srcCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}

		var sv freebsd.Advisory
		if err := json.Unmarshal(sbs, &sv); err != nil {
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
			y := "others"
			if strings.HasPrefix(id, "CVE-") {
				y = strings.Split(id, "-")[1]
				if _, err := strconv.Atoi(y); err != nil {
					return nil
				}
			}

			dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, id))
			}

			var dv build.Vulnerability
			if len(dvbs) > 0 {
				if err := json.Unmarshal(dvbs, &dv); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillVulnerability(&dv, &sv, id)

			dvbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, id))
			}

			ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, y, id))
			}

			var dd build.DetectPackage
			if len(ddbs) > 0 {
				if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillDetect(&dd, id, &sv)

			ddbs, err = json.Marshal(dd)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, id))
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
