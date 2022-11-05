package arch

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

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/arch"
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
		srcDir:        filepath.Join(util.SourceDir(), "arch"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "arch"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build Arch Linux")
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

		var sv arch.VulnerabilityGroup
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, cve := range sv.Issues {
			if err := func() error {
				y := strings.Split(cve, "-")[1]
				if _, err := strconv.Atoi(y); err != nil {
					return nil
				}
				if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
				}
				if err := os.MkdirAll(filepath.Join(options.destDetectDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, y))
				}

				dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve)))
				}
				defer dvf.Close()

				var dv build.Vulnerability
				if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillVulnerability(&dv, &sv, cve)

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

				ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", cve)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", cve)))
				}
				defer ddf.Close()

				var dd build.DetectPackage
				if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillDetect(&dd, cve, &sv)

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
		return errors.Wrap(err, "walk arch")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *arch.VulnerabilityGroup, cve string) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.Arch = append(dv.Advisory.Arch, build.Advisory{
		ID:  sv.Name,
		URL: fmt.Sprintf("https://security.archlinux.org/%s", sv.Name),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.Arch == nil {
		dv.Title.Arch = map[string]string{}
	}
	dv.Title.Arch[sv.Name] = sv.Name

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.Arch == nil {
		dv.CVSS.Arch = map[string][]build.CVSS{}
	}
	dv.CVSS.Arch[sv.Name] = append(dv.CVSS.Arch[sv.Name], build.CVSS{
		Source:   "ArchLinux",
		Severity: sv.Severity,
	})

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.Arch == nil {
		dv.References.Arch = map[string][]build.Reference{}
	}
	if sv.Ticket != "" {
		dv.References.Arch[sv.Name] = append(dv.References.Arch[sv.Name], build.Reference{
			Source: "ARCHBUG",
			Name:   fmt.Sprintf("FS#%s", sv.Ticket),
			URL:    fmt.Sprintf("https://bugs.archlinux.org/task/%s", sv.Ticket),
		})
	}
	for _, a := range sv.Advisories {
		dv.References.Arch[sv.Name] = append(dv.References.Arch[sv.Name], build.Reference{
			Source: "ARCH",
			Name:   a,
			URL:    fmt.Sprintf("https://security.archlinux.org/%s", a),
		})
	}
}

func fillDetect(dd *build.DetectPackage, cve string, sv *arch.VulnerabilityGroup) {
	if dd.ID == "" {
		dd.ID = cve
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for _, p := range sv.Packages {
		var vs []build.Version
		if sv.Affected != "" {
			vs = append(vs, build.Version{
				Operator: "ge",
				Version:  sv.Affected,
			})
		}
		if sv.Fixed != "" {
			vs = append(vs, build.Version{
				Operator: "lt",
				Version:  sv.Fixed,
			})
		}

		dd.Packages[sv.Name] = append(dd.Packages[sv.Name], build.Package{
			Name:    p,
			Status:  sv.Status,
			Version: [][]build.Version{vs},
		})
	}
}
