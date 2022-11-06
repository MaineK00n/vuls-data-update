package tracker

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/tracker"
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
		srcDir:        filepath.Join(util.SourceDir(), "ubuntu", "tracker"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "ubuntu", "tracker"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build Ubuntu Security Tracker")
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

		var sv tracker.Advisory
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		y := strings.Split(sv.Candidate, "-")[1]
		if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
		}

		dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Candidate)), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Candidate)))
		}
		defer dvf.Close()

		var dv build.Vulnerability
		if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "decode json")
		}

		fillVulnerability(&dv, &sv)

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

		v := filepath.Base(filepath.Dir(filepath.Dir(path)))
		if err := os.MkdirAll(filepath.Join(options.destDetectDir, v, y), os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, v, y))
		}

		ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.Candidate)), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.Candidate)))
		}
		defer ddf.Close()

		var dd build.DetectPackage
		if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "decode json")
		}

		fillDetect(&dd, &sv)

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
	}); err != nil {
		return errors.Wrap(err, "walk tracker")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *tracker.Advisory) {
	if dv.ID == "" {
		dv.ID = sv.Candidate
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.UbuntuSecurityTracker = &build.Advisory{
		ID:  sv.Candidate,
		URL: fmt.Sprintf("https://ubuntu.com/security/%s", sv.Candidate),
	}

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	dv.Title.UbuntuSecurityTracker = sv.Candidate

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	dv.Description.UbuntuSecurityTracker = sv.Description
	if sv.UbuntuDescription != "" {
		dv.Description.UbuntuSecurityTracker = fmt.Sprintf("%s %s", sv.Description, sv.UbuntuDescription)
	}

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	var cs []build.CVSS
	if sv.Priority != "" {
		cs = append(cs, build.CVSS{
			Source:   "UBUNTU",
			Severity: sv.Priority,
		})
	}
	for source, c := range sv.CVSS {
		bc := build.CVSS{
			Source:   source,
			Version:  "2.0",
			Vector:   c.Vector,
			Score:    &c.Score,
			Severity: c.Severity,
		}
		if strings.HasPrefix(c.Vector, "CVSS:3.0") {
			bc.Version = "3.0"
		} else if strings.HasPrefix(c.Vector, "CVSS:3.1") {
			bc.Version = "3.1"
		}
		cs = append(cs, bc)
	}
	dv.CVSS.UbuntuSecurityTracker = cs

	if sv.Mitigation != "" {
		if dv.Mitigation == nil {
			dv.Mitigation = &build.Mitigation{}
		}
		dv.Mitigation.UbuntuSecurityTracker = sv.Mitigation
	}

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if sv.PublicDate != nil {
		dv.Published.UbuntuSecurityTracker = sv.PublicDate
	}
	if sv.CRD != nil {
		dv.Published.UbuntuSecurityTracker = sv.CRD
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	var rs []build.Reference
	for _, b := range sv.Bugs {
		rs = append(rs, build.Reference{
			Source: "BUG",
			Name:   b,
			URL:    b,
		})
	}
	for _, r := range sv.References {
		rs = append(rs, build.Reference{
			Source: "MISC",
			Name:   r,
			URL:    r,
		})
	}
	dv.References.UbuntuSecurityTracker = rs
}

func fillDetect(dd *build.DetectPackage, sv *tracker.Advisory) {
	if dd.ID == "" {
		dd.ID = sv.Candidate
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for _, p := range sv.Packages {
		bp := build.Package{
			Name:   p.Name,
			Status: p.Status,
		}
		if p.Status == "released" {
			bp.Version = [][]build.Version{{{Operator: "lt", Version: p.Note}}}
		}
		dd.Packages[sv.Candidate] = append(dd.Packages[sv.Candidate], bp)
	}
}
