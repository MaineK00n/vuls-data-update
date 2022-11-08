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
		srcDir:             filepath.Join(util.SourceDir(), "arch"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "arch"),
		destCompressFormat: "",
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

		sbs, err := util.Open(path, options.srcCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}

		var sv arch.VulnerabilityGroup
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, cve := range sv.Issues {
			y := strings.Split(cve, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				log.Printf(`[WARN] unexpected CVE-ID. accepts: "CVE-yyyy-XXXX", received: "%s"`, cve)
				continue
			}

			dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, cve))
			}

			var dv build.Vulnerability
			if len(dvbs) > 0 {
				if err := json.Unmarshal(dvbs, &dv); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillVulnerability(&dv, &sv, cve)

			dvbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, cve))
			}

			ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, y, cve))
			}

			var dd build.DetectPackage
			if len(ddbs) > 0 {
				if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillDetect(&dd, cve, &sv)

			ddbs, err = json.Marshal(dd)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, cve))
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
			Source: "BUG",
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
