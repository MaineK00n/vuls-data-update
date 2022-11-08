package oval

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/oval"
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
		srcDir:             filepath.Join(util.SourceDir(), "ubuntu", "oval"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "ubuntu", "oval"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build Ubuntu OVAL")
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

		var sv oval.Definition
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, r := range sv.References {
			if r.Source != "CVE" {
				continue
			}

			v := filepath.Base(filepath.Dir(path))
			y := strings.Split(r.ID, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				log.Printf(`[WARN] unexpected CVE-ID. accepts: "CVE-yyyy-XXXX", received: "%s"`, r.ID)
				continue
			}

			dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.ID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, r.ID))
			}

			var dv build.Vulnerability
			if len(dvbs) > 0 {
				if err := json.Unmarshal(dvbs, &dv); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillVulnerability(&dv, &sv, r.ID, v)

			dvbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.ID)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, r.ID))
			}

			ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", r.ID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, r.ID))
			}

			var dd build.DetectPackage
			if len(ddbs) > 0 {
				if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillDetect(&dd, r.ID, &sv)

			ddbs, err = json.Marshal(dd)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", r.ID)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, v, y, r.ID))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk oval")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *oval.Definition, cve, version string) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.UbuntuOVAL == nil {
		dv.Advisory.UbuntuOVAL = map[string][]build.Advisory{}
	}
	dv.Advisory.UbuntuOVAL[version] = append(dv.Advisory.UbuntuOVAL[version], build.Advisory{
		ID:  sv.DefinitionID,
		URL: fmt.Sprintf("https://ubuntu.com/security/%s", cve),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.UbuntuOVAL == nil {
		dv.Title.UbuntuOVAL = map[string]map[string]string{}
	}
	if dv.Title.UbuntuOVAL[version] == nil {
		dv.Title.UbuntuOVAL[version] = map[string]string{}
	}
	dv.Title.UbuntuOVAL[version][sv.DefinitionID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.UbuntuOVAL == nil {
		dv.Description.UbuntuOVAL = map[string]map[string]string{}
	}
	if dv.Description.UbuntuOVAL[version] == nil {
		dv.Description.UbuntuOVAL[version] = map[string]string{}
	}
	dv.Description.UbuntuOVAL[version][sv.DefinitionID] = sv.Description

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.UbuntuOVAL == nil {
		dv.CVSS.UbuntuOVAL = map[string]map[string][]build.CVSS{}
	}
	if dv.CVSS.UbuntuOVAL[version] == nil {
		dv.CVSS.UbuntuOVAL[version] = map[string][]build.CVSS{}
	}
	dv.CVSS.UbuntuOVAL[version][sv.DefinitionID] = append(dv.CVSS.UbuntuOVAL[version][sv.DefinitionID], build.CVSS{
		Source:   "UBUNTU",
		Severity: sv.Advisory.Severity,
	})

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.UbuntuOVAL == nil {
		dv.Published.UbuntuOVAL = map[string]map[string]*time.Time{}
	}
	if dv.Published.UbuntuOVAL[version] == nil {
		dv.Published.UbuntuOVAL[version] = map[string]*time.Time{}
	}
	if sv.Advisory.PublicDate != nil {
		dv.Published.UbuntuOVAL[version][sv.DefinitionID] = sv.Advisory.PublicDate
	}
	if sv.Advisory.CRD != nil {
		dv.Published.UbuntuOVAL[version][sv.DefinitionID] = sv.Advisory.CRD
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.UbuntuOVAL == nil {
		dv.References.UbuntuOVAL = map[string]map[string][]build.Reference{}
	}
	if dv.References.UbuntuOVAL[version] == nil {
		dv.References.UbuntuOVAL[version] = map[string][]build.Reference{}
	}
	for _, b := range sv.Advisory.Bugzillas {
		dv.References.UbuntuOVAL[version][sv.DefinitionID] = append(dv.References.UbuntuOVAL[version][sv.DefinitionID], build.Reference{
			Source: "BUG",
			Name:   b,
			URL:    fmt.Sprintf("https://bugs.launchpad.net/ubuntu/+bug/%s", b),
		})
	}
	for _, r := range sv.Advisory.References {
		dv.References.UbuntuOVAL[version][sv.DefinitionID] = append(dv.References.UbuntuOVAL[version][sv.DefinitionID], build.Reference{
			Source: "UBUNTU",
			Name:   r,
			URL:    r,
		})
	}
	for _, r := range sv.References {
		dv.References.UbuntuOVAL[version][sv.DefinitionID] = append(dv.References.UbuntuOVAL[version][sv.DefinitionID], build.Reference{
			Source: r.Source,
			Name:   r.ID,
			URL:    r.URL,
		})
	}
}

func fillDetect(dd *build.DetectPackage, cve string, sv *oval.Definition) {
	if dd.ID == "" {
		dd.ID = cve
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for _, p := range sv.Packages {
		bp := build.Package{
			Name:   p.Name,
			Status: p.Status,
		}
		if p.FixedVersion != "" {
			bp.Version = [][]build.Version{{{Operator: "lt", Version: p.FixedVersion}}}
		}
		dd.Packages[sv.DefinitionID] = append(dd.Packages[sv.DefinitionID], bp)
	}
}
