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

	"github.com/knqyf263/go-version"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/suse/oval"
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
		srcDir:        filepath.Join(util.SourceDir(), "suse", "oval"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "suse", "oval"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build SUSE OVAL")
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

		verpkgs := map[string][]oval.Package{}
		for _, p := range sv.Packages {
			v, err := getOSVersion(p.Platform)
			if err != nil {
				log.Printf(`[WARN] %s`, err)
				continue
			}
			if v != "" {
				verpkgs[v] = append(verpkgs[v], p)
			}
		}

		osname := filepath.Base(filepath.Dir(filepath.Dir(path)))
		for _, cve := range sv.Advisory.CVEs {
			y := strings.Split(cve.CVEID, "-")[1]
			if err := func() error {
				if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
				}

				dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve.CVEID)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve.CVEID)))
				}
				defer dvf.Close()

				var dv build.Vulnerability
				if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillVulnerability(&dv, &sv, cve, fmt.Sprintf("%s.%s", osname, filepath.Base(filepath.Dir(path))))

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

				return nil
			}(); err != nil {
				return err
			}

			for v, pkgs := range verpkgs {
				if err := func() error {
					if err := os.MkdirAll(filepath.Join(options.destDetectDir, osname, v, y), os.ModePerm); err != nil {
						return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, osname, v, y))
					}

					ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, osname, v, y, fmt.Sprintf("%s.json", cve.CVEID)), os.O_RDWR|os.O_CREATE, 0644)
					if err != nil {
						return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, osname, v, y, fmt.Sprintf("%s.json", cve.CVEID)))
					}
					defer ddf.Close()

					var dd build.DetectPackage
					if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
						return errors.Wrap(err, "decode json")
					}

					fillDetect(&dd, cve.CVEID, sv.DefinitionID, pkgs)

					if err := ddf.Truncate(0); err != nil {
						return errors.Wrap(err, "truncate file")
					}
					if _, err := ddf.Seek(0, 0); err != nil {
						return errors.Wrap(err, "set offset")
					}
					enc := json.NewEncoder(ddf)
					enc.SetIndent("", "  ")
					if err := enc.Encode(dd); err != nil {
						return errors.Wrap(err, "encode json")
					}

					return nil
				}(); err != nil {
					return err
				}
			}

		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk oval")
	}

	return nil
}

func getOSVersion(platform string) (string, error) {
	if strings.HasPrefix(platform, "suse") {
		s := strings.TrimPrefix(platform, "suse")
		if len(s) < 3 {
			return "", errors.Errorf(`unexpected version string. expected: "suse\d{3}(-.+)?", actual: "%s"`, platform)
		}
		lhs, _, _ := strings.Cut(s, "-")
		v := fmt.Sprintf("%s.%s", lhs[:2], lhs[2:])
		if _, err := version.NewVersion(v); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		return v, nil
	}

	if strings.HasPrefix(platform, "sled") {
		s := strings.TrimPrefix(platform, "sled")
		major, rhs, found := strings.Cut(s, "-")
		if _, err := version.NewVersion(major); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		if !found {
			return major, nil
		}
		for _, s := range strings.Split(rhs, "-") {
			if strings.HasPrefix(s, "sp") {
				sp, err := strconv.Atoi(strings.TrimPrefix(s, "sp"))
				if err != nil {
					return "", errors.Wrap(err, "parse sp version")
				}
				v := major
				if sp != 0 {
					v = fmt.Sprintf("%s.%d", major, sp)
				}
				if _, err := version.NewVersion(v); err != nil {
					return "", errors.Wrap(err, "parse version")
				}
				return v, nil
			}
		}
		return major, nil
	}

	if strings.HasPrefix(platform, "sles") {
		s := strings.TrimPrefix(platform, "sles")
		major, rhs, found := strings.Cut(s, "-")
		if _, err := version.NewVersion(major); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		if !found {
			return major, nil
		}
		for _, s := range strings.Split(rhs, "-") {
			if strings.HasPrefix(s, "sp") {
				sp, err := strconv.Atoi(strings.TrimPrefix(s, "sp"))
				if err != nil {
					return "", errors.Wrap(err, "parse sp version")
				}
				v := major
				if sp != 0 {
					v = fmt.Sprintf("%s.%d", major, sp)
				}
				if _, err := version.NewVersion(v); err != nil {
					return "", errors.Wrap(err, "parse version")
				}
				return v, nil
			}
		}
		return major, nil
	}

	if strings.HasPrefix(platform, "core9") {
		return "9", nil
	}

	if strings.HasPrefix(platform, "openSUSE") {
		if strings.HasPrefix(platform, "openSUSE Leap") {
			if strings.HasPrefix(platform, "openSUSE Leap Micro") {
				return "", nil
			}

			// e.g. openSUSE Leap 15.0
			ss := strings.Fields(platform)
			if len(ss) < 3 {
				return "", errors.Errorf(`unexpected version string. expected: "openSUSE Leap <Version>", actual: "%s"`, platform)
			}
			if _, err := version.NewVersion(ss[2]); err != nil {
				return "", errors.Wrap(err, "parse version")
			}
			return ss[2], nil
		}
		// e.g. openSUSE 13.2, openSUSE Tumbleweed
		ss := strings.Fields(platform)
		if len(ss) < 2 {
			return "", errors.Errorf(`unexpected version string. expected: "openSUSE <Version>", actual: "%s"`, platform)
		}
		if ss[1] == "Tumbleweed" {
			return "tumbleweed", nil
		}
		if _, err := version.NewVersion(ss[1]); err != nil {
			return "", errors.Wrap(err, "parse version")
		}
		return ss[1], nil
	}

	if strings.HasPrefix(platform, "SUSE Linux Enterprise") {
		// e.g. SUSE Linux Enterprise Storage 7, SUSE Linux Enterprise Micro 5.1
		if strings.HasPrefix(platform, "SUSE Linux Enterprise Storage") || strings.HasPrefix(platform, "SUSE Linux Enterprise Micro") {
			return "", nil
		}

		ss := strings.Fields(strings.ReplaceAll(platform, "-", " "))
		vs := make([]string, 0, 2)
		for i := len(ss) - 1; i > 0; i-- {
			v, err := strconv.Atoi(strings.TrimPrefix(ss[i], "SP"))
			if err != nil {
				continue
			}
			vs = append(vs, fmt.Sprintf("%d", v))
			if len(vs) == 2 {
				break
			}
		}
		switch len(vs) {
		case 0:
			return "", errors.Errorf(`unexpected version string. expected: "SUSE Linux Enterprise ... <Major Version>(-SP<MINOR Version>)", actual: "%s"`, platform)
		case 1:
			if _, err := version.NewVersion(vs[0]); err != nil {
				return "", errors.Wrap(err, "parse version")
			}
			return vs[0], nil
		case 2:
			if _, err := version.NewVersion(vs[1]); err != nil {
				return "", errors.Wrap(err, "parse major version")
			}
			if _, err := version.NewVersion(vs[0]); err != nil {
				return "", errors.Wrap(err, "parse minor version")
			}
			return fmt.Sprintf("%s.%s", vs[1], vs[0]), nil
		}

		return "", errors.Errorf(`unexpected version string. expected: "SUSE Linux Enterprise .+ <Major Version>.*( SP\d.*)?", actual: "%s"`, platform)
	}

	if strings.HasPrefix(platform, "SUSE Manager") {
		// e.g. SUSE Manager Proxy 4.0, SUSE Manager Server 4.0
		return "", nil
	}

	return "", errors.Errorf(`not support platform. platform: "%s"`, platform)
}

func fillVulnerability(dv *build.Vulnerability, sv *oval.Definition, cve oval.CVE, version string) {
	if dv.ID == "" {
		dv.ID = cve.CVEID
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.SUSEOVAL == nil {
		dv.Advisory.SUSEOVAL = map[string][]build.Advisory{}
	}
	dv.Advisory.SUSEOVAL[version] = append(dv.Advisory.SUSEOVAL[version], build.Advisory{
		ID:  sv.DefinitionID,
		URL: fmt.Sprintf("https://www.suse.com/security/cve/%s.html", cve.CVEID),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.SUSEOVAL == nil {
		dv.Title.SUSEOVAL = map[string]map[string]string{}
	}
	if dv.Title.SUSEOVAL[version] == nil {
		dv.Title.SUSEOVAL[version] = map[string]string{}
	}
	dv.Title.SUSEOVAL[version][sv.DefinitionID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.SUSEOVAL == nil {
		dv.Description.SUSEOVAL = map[string]map[string]string{}
	}
	if dv.Description.SUSEOVAL[version] == nil {
		dv.Description.SUSEOVAL[version] = map[string]string{}
	}
	dv.Description.SUSEOVAL[version][sv.DefinitionID] = sv.Description

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.SUSEOVAL == nil {
		dv.CVSS.SUSEOVAL = map[string]map[string][]build.CVSS{}
	}
	if dv.CVSS.SUSEOVAL[version] == nil {
		dv.CVSS.SUSEOVAL[version] = map[string][]build.CVSS{}
	}
	var cvsses []build.CVSS
	if cve.CVSS3 != "" {
		c := build.CVSS{
			Source:   "SUSE",
			Severity: cve.Impact,
		}
		lhs, rhs, found := strings.Cut(cve.CVSS3, "/")
		if found {
			c.Version = "3.0"
			if strings.HasPrefix(rhs, "CVSS:3.1") {
				c.Version = "3.1"
			}
			c.Vector = rhs
			if s, err := strconv.ParseFloat(lhs, 64); err == nil {
				c.Score = &s
			} else {
				log.Printf(`[WARN] unexpected CVSS3 Base Score. accepts: float64, received: "%s"`, lhs)
			}
		} else {
			log.Printf(`[WARN] unexpected CVSS3 string. accepts: "<Base Score>/<CVSS3 Vector>", received: "%s"`, cve.CVSS3)
		}
		cvsses = append(cvsses, c)
	}
	if len(cvsses) == 0 && cve.Impact != "" {
		cvsses = append(cvsses, build.CVSS{
			Source:   "SUSE",
			Severity: cve.Impact,
		})
	}
	if len(cvsses) > 0 {
		dv.CVSS.SUSEOVAL[version][sv.DefinitionID] = cvsses
	}

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.SUSEOVAL == nil {
		dv.Published.SUSEOVAL = map[string]map[string]*time.Time{}
	}
	if dv.Published.SUSEOVAL[version] == nil {
		dv.Published.SUSEOVAL[version] = map[string]*time.Time{}
	}
	if sv.Advisory.Issued != nil {
		dv.Published.SUSEOVAL[version][sv.DefinitionID] = sv.Advisory.Issued
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if dv.Modified.SUSEOVAL == nil {
		dv.Modified.SUSEOVAL = map[string]map[string]*time.Time{}
	}
	if dv.Modified.SUSEOVAL[version] == nil {
		dv.Modified.SUSEOVAL[version] = map[string]*time.Time{}
	}
	if sv.Advisory.Updated != nil {
		dv.Modified.SUSEOVAL[version][sv.DefinitionID] = sv.Advisory.Updated
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.SUSEOVAL == nil {
		dv.References.SUSEOVAL = map[string]map[string][]build.Reference{}
	}
	if dv.References.SUSEOVAL[version] == nil {
		dv.References.SUSEOVAL[version] = map[string][]build.Reference{}
	}
	for _, b := range sv.Advisory.Bugzillas {
		dv.References.SUSEOVAL[version][sv.DefinitionID] = append(dv.References.SUSEOVAL[version][sv.DefinitionID], build.Reference{
			Source: "SUSEBUG",
			Name:   b.Title,
			URL:    b.URL,
		})
	}
	for _, r := range sv.References {
		dv.References.SUSEOVAL[version][sv.DefinitionID] = append(dv.References.SUSEOVAL[version][sv.DefinitionID], build.Reference{
			Source: r.Source,
			Name:   r.ID,
			URL:    r.URL,
		})
	}
}

func fillDetect(dd *build.DetectPackage, cve, definitionID string, pkgs []oval.Package) {
	if dd.ID == "" {
		dd.ID = cve
	}

	type pkg struct {
		name     string
		status   string
		version  string
		kversion string
	}
	ps := map[pkg][]string{}
	for _, p := range pkgs {
		if ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, kversion: p.KernelDefaultVersion}] == nil {
			ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, kversion: p.KernelDefaultVersion}] = []string{}
		}
		if p.Arch != "" {
			ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, kversion: p.KernelDefaultVersion}] = append(ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, kversion: p.KernelDefaultVersion}], p.Arch)
		}
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for p, arches := range ps {
		v := [][]build.Version{{{Operator: "lt", Version: p.version}}}
		if p.version == "" {
			v = nil
		}
		dd.Packages[definitionID] = append(dd.Packages[definitionID], build.Package{
			Name:    p.name,
			Status:  p.status,
			Version: v,
			Arch:    util.Unique(arches),
		})
	}
}
