package tracker

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

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/tracker"
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
		srcDir:             filepath.Join(util.SourceDir(), "ubuntu", "tracker"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "ubuntu", "tracker"),
		destCompressFormat: "",
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

		sbs, err := util.Open(path, options.srcCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}

		var sv tracker.Advisory
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		v := filepath.Base(filepath.Dir(filepath.Dir(path)))
		y := strings.Split(sv.Candidate, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			log.Printf(`[WARN] unexpected CVE-ID. accepts: "CVE-yyyy-XXXX", received: "%s"`, sv.Candidate)
			return nil
		}

		dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Candidate)), options.destCompressFormat), options.destCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, sv.Candidate))
		}

		var dv build.Vulnerability
		if len(dvbs) > 0 {
			if err := json.Unmarshal(dvbs, &dv); err != nil {
				return errors.Wrap(err, "unmarshal json")
			}
		}

		fillVulnerability(&dv, &sv)

		dvbs, err = json.Marshal(dv)
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Candidate)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, sv.Candidate))
		}

		ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.Candidate)), options.destCompressFormat), options.destCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, sv.Candidate))
		}

		var dd build.DetectPackage
		if len(ddbs) > 0 {
			if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
				return errors.Wrap(err, "unmarshal json")
			}
		}

		fillDetect(&dd, &sv)

		ddbs, err = json.Marshal(dd)
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.Candidate)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, v, y, sv.Candidate))
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
