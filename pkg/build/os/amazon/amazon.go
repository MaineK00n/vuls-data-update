package amazon

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

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/amazon"
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
		srcDir:        filepath.Join(util.SourceDir(), "amazon"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "amazon"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build Amazon Linux")
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

		var sv amazon.Advisory
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
			if _, err := strconv.Atoi(y); err != nil {
				continue
			}
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

			fillVulnerability(&dv, &sv, r.ID, v)

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

			ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", r.ID)), os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", r.ID)))
			}
			defer ddf.Close()

			var dd build.DetectPackage
			if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
				return errors.Wrap(err, "decode json")
			}

			fillDetect(&dd, r.ID, &sv)

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
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk amazon")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *amazon.Advisory, cve, version string) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.Amazon == nil {
		dv.Advisory.Amazon = map[string][]build.Advisory{}
	}
	var u string
	switch version {
	case "1":
		u = fmt.Sprintf("https://alas.aws.amazon.com/ALAS%s.html", strings.TrimPrefix(sv.ID, "ALAS"))
	case "2":
		u = fmt.Sprintf("https://alas.aws.amazon.com/AL2/ALAS%s.html", strings.TrimPrefix(sv.ID, "ALAS2"))
	case "2022":
		u = fmt.Sprintf("https://alas.aws.amazon.com/AL2022/ALAS%s.html", strings.TrimPrefix(sv.ID, "ALAS2022"))
	}
	dv.Advisory.Amazon[version] = append(dv.Advisory.Amazon[version], build.Advisory{
		ID:  sv.ID,
		URL: u,
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.Amazon == nil {
		dv.Title.Amazon = map[string]map[string]string{}
	}
	if dv.Title.Amazon[version] == nil {
		dv.Title.Amazon[version] = map[string]string{}
	}
	dv.Title.Amazon[version][sv.ID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.Amazon == nil {
		dv.Description.Amazon = map[string]map[string]string{}
	}
	if dv.Description.Amazon[version] == nil {
		dv.Description.Amazon[version] = map[string]string{}
	}
	dv.Description.Amazon[version][sv.ID] = sv.Description

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.Amazon == nil {
		dv.Published.Amazon = map[string]map[string]*time.Time{}
	}
	if dv.Published.Amazon[version] == nil {
		dv.Published.Amazon[version] = map[string]*time.Time{}
	}
	if sv.Issued != nil {
		dv.Published.Amazon[version][sv.ID] = sv.Issued
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if dv.Modified.Amazon == nil {
		dv.Modified.Amazon = map[string]map[string]*time.Time{}
	}
	if dv.Modified.Amazon[version] == nil {
		dv.Modified.Amazon[version] = map[string]*time.Time{}
	}
	if sv.Updated != nil {
		dv.Modified.Amazon[version][sv.ID] = sv.Updated
	}

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.Amazon == nil {
		dv.CVSS.Amazon = map[string]map[string][]build.CVSS{}
	}
	if dv.CVSS.Amazon[version] == nil {
		dv.CVSS.Amazon[version] = map[string][]build.CVSS{}
	}
	dv.CVSS.Amazon[version][sv.ID] = append(dv.CVSS.Amazon[version][sv.ID], build.CVSS{
		Source:   "AmazonLinux",
		Severity: sv.Severity,
	})

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.Amazon == nil {
		dv.References.Amazon = map[string]map[string][]build.Reference{}
	}
	if dv.References.Amazon[version] == nil {
		dv.References.Amazon[version] = map[string][]build.Reference{}
	}
	for _, r := range sv.References {
		dv.References.Amazon[version][sv.ID] = append(dv.References.Amazon[version][sv.ID], build.Reference{
			Source: r.Type,
			Name:   r.ID,
			URL:    r.Href,
		})
	}
}

func fillDetect(dd *build.DetectPackage, cve string, sv *amazon.Advisory) {
	if dd.ID == "" {
		dd.ID = cve
	}

	type pkg struct {
		name    string
		epoch   string
		version string
		release string
	}
	ps := map[pkg][]string{}
	for _, p := range sv.Pkglist.Package {
		ps[pkg{name: p.Name, epoch: p.Epoch, version: p.Version, release: p.Release}] = append(ps[pkg{name: p.Name, epoch: p.Epoch, version: p.Version, release: p.Release}], p.Arch)
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for _, p := range sv.Pkglist.Package {
		dd.Packages[sv.ID] = append(dd.Packages[sv.ID], build.Package{
			Name:    p.Name,
			Status:  "fixed",
			Version: [][]build.Version{{{Operator: "lt", Version: constructVersion(p.Epoch, p.Version, p.Release)}}},
			Arch:    ps[pkg{name: p.Name, epoch: p.Epoch, version: p.Version, release: p.Release}],
		})
	}
}

func constructVersion(epoch, version, release string) string {
	if epoch == "" || epoch == "0" {
		return fmt.Sprintf("%s-%s", version, release)
	}
	return fmt.Sprintf("%s:%s-%s", epoch, version, release)
}
