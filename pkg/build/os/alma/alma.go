package alma

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/alma"
	"github.com/pkg/errors"
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
		srcDir:        filepath.Join(util.SourceDir(), "alma"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "alma"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build AlmaLinux")
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

		var sv alma.Advisory
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, r := range sv.References {
			if r.Type != "cve" {
				continue
			}

			dir, _ := filepath.Split(filepath.Dir(path))
			v := filepath.Base(dir)
			y := strings.Split(r.ID, "-")[1]
			if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
			}
			if err := os.MkdirAll(filepath.Join(options.destDetectDir, v, y), os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, v, y))
			}

			dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.ID)), os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.ID)))
			}
			defer dvf.Close()

			var dv build.Vulnerability
			if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
				return errors.Wrap(err, "decode json")
			}

			fillVulnerability(r.ID, v, &sv, &dv)

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

			ddf, err := os.Create(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", r.ID)))
			if err != nil {
				return errors.Wrapf(err, "create %s", filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", r.ID)))
			}
			defer ddf.Close()

			dd := getDetect(r.ID, &sv)

			enc = json.NewEncoder(ddf)
			enc.SetIndent("", "  ")
			if err := enc.Encode(dd); err != nil {
				return errors.Wrap(err, "encode json")
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk alma")
	}

	return nil
}

func fillVulnerability(cve, version string, sv *alma.Advisory, dv *build.Vulnerability) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.Alma = append(dv.Advisory.Alma, build.Advisory{
		ID:  sv.ID,
		URL: fmt.Sprintf("https://errata.almalinux.org/%s/%s.html", version, strings.ReplaceAll(sv.ID, ":", "-")),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.Alma == nil {
		dv.Title.Alma = map[string]string{}
	}
	dv.Title.Alma[sv.ID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.Alma == nil {
		dv.Description.Alma = map[string]string{}
	}
	dv.Description.Alma[sv.ID] = sv.Description

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.Alma == nil {
		dv.Published.Alma = map[string]*time.Time{}
	}
	if sv.IssuedDate != nil {
		dv.Published.Alma[sv.ID] = sv.IssuedDate
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if dv.Modified.Alma == nil {
		dv.Modified.Alma = map[string]*time.Time{}
	}
	if sv.UpdatedDate != nil {
		dv.Modified.Alma[sv.ID] = sv.UpdatedDate
	}

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.Alma == nil {
		dv.CVSS.Alma = map[string][]build.CVSS{}
	}
	dv.CVSS.Alma[sv.ID] = append(dv.CVSS.Alma[sv.ID], build.CVSS{
		Source:   "AlmaLinux",
		Severity: sv.Severity,
	})

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.Alma == nil {
		dv.References.Alma = map[string][]build.Reference{}
	}
	for _, r := range sv.References {
		source := "MISC"
		if r.Type == "self" {
			source = "ALMA"
		}
		dv.References.Alma[sv.ID] = append(dv.References.Alma[sv.ID], build.Reference{
			Source: source,
			Name:   r.ID,
			URL:    r.Href,
		})
	}
}

func getDetect(cve string, sv *alma.Advisory) build.DetectPackage {
	d := build.DetectPackage{
		ID: cve,
	}

	type pkg struct {
		name    string
		epoch   string
		version string
		release string
		module  string
	}
	ps := map[pkg][]string{}
	for _, p := range sv.Packages {
		ps[pkg{name: p.Name, epoch: p.Epoch, version: p.Version, release: p.Release, module: p.Module}] = append(ps[pkg{name: p.Name, epoch: p.Epoch, version: p.Version, release: p.Release, module: p.Module}], p.Arch)
	}
	for _, p := range sv.Packages {
		d.Packages = append(d.Packages, build.Package{
			Name:            p.Name,
			Status:          "fixed",
			FixedVersion:    constructVersion(p.Epoch, p.Version, p.Release),
			ModularityLabel: p.Module,
			Arch:            ps[pkg{name: p.Name, epoch: p.Epoch, version: p.Version, release: p.Release, module: p.Module}],
		})
	}
	return d
}

func constructVersion(epoch, version, release string) string {
	if epoch == "" || epoch == "0" {
		return fmt.Sprintf("%s-%s", version, release)
	}
	return fmt.Sprintf("%s:%s-%s", epoch, version, release)
}