package oval

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

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/oval"
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
		srcDir:        filepath.Join(util.SourceDir(), "ubuntu", "oval"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "ubuntu", "oval"),
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

		sf, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer sf.Close()

		var sv oval.Definition
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, r := range sv.References {
			if err := func() error {
				if r.Source != "CVE" {
					return nil
				}

				v := filepath.Base(filepath.Dir(path))
				y := strings.Split(r.ID, "-")[1]
				if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
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

				if err := os.MkdirAll(filepath.Join(options.destDetectDir, v, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, v, y))
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

				fillDetect(&dd, &sv, r.ID)

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
			Source: "UBUNTUBUG",
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

func fillDetect(dd *build.DetectPackage, sv *oval.Definition, cve string) {
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
