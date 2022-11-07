package oracle

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/oracle"
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
		srcDir:             filepath.Join(util.SourceDir(), "oracle"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "oracle"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build Oracle Linux")
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

		var sv oracle.Definition
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, cve := range sv.Advisory.Cves {
			v := strings.TrimPrefix(sv.Affected.Platform, "Oracle Linux ")
			y := strings.Split(cve, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				return nil
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

			fillVulnerability(&dv, &sv, cve, v)

			dvbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, cve))
			}

			ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, cve))
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

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, v, y, cve))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk oracle")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *oracle.Definition, cve, version string) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.Oracle == nil {
		dv.Advisory.Oracle = map[string][]build.Advisory{}
	}
	dv.Advisory.Oracle[version] = append(dv.Advisory.Oracle[version], build.Advisory{
		ID:  sv.DefinitionID,
		URL: fmt.Sprintf("https://linux.oracle.com/errata/ELSA-%s-%s.html", strings.TrimPrefix(sv.DefinitionID, "oval:com.oracle.elsa:def:")[0:4], strings.TrimPrefix(sv.DefinitionID, "oval:com.oracle.elsa:def:")[4:]),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.Oracle == nil {
		dv.Title.Oracle = map[string]map[string]string{}
	}
	if dv.Title.Oracle[version] == nil {
		dv.Title.Oracle[version] = map[string]string{}
	}
	dv.Title.Oracle[version][sv.DefinitionID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.Oracle == nil {
		dv.Description.Oracle = map[string]map[string]string{}
	}
	if dv.Description.Oracle[version] == nil {
		dv.Description.Oracle[version] = map[string]string{}
	}
	dv.Description.Oracle[version][sv.DefinitionID] = sv.Description

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.Oracle == nil {
		dv.Published.Oracle = map[string]map[string]*time.Time{}
	}
	if dv.Published.Oracle[version] == nil {
		dv.Published.Oracle[version] = map[string]*time.Time{}
	}
	if sv.Advisory.Issued != nil {
		dv.Published.Oracle[version][sv.DefinitionID] = sv.Advisory.Issued
	}

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.Oracle == nil {
		dv.CVSS.Oracle = map[string]map[string][]build.CVSS{}
	}
	if dv.CVSS.Oracle[version] == nil {
		dv.CVSS.Oracle[version] = map[string][]build.CVSS{}
	}
	dv.CVSS.Oracle[version][sv.DefinitionID] = append(dv.CVSS.Oracle[version][sv.DefinitionID], build.CVSS{
		Source:   "Oracle",
		Severity: sv.Advisory.Severity,
	})

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.Oracle == nil {
		dv.References.Oracle = map[string]map[string][]build.Reference{}
	}
	if dv.References.Oracle[version] == nil {
		dv.References.Oracle[version] = map[string][]build.Reference{}
	}
	for _, r := range sv.References {
		dv.References.Oracle[version][sv.DefinitionID] = append(dv.References.Oracle[version][sv.DefinitionID], build.Reference{
			Source: r.Source,
			Name:   r.ID,
			URL:    r.URL,
		})
	}
}

func fillDetect(dd *build.DetectPackage, cve string, sv *oracle.Definition) {
	if dd.ID == "" {
		dd.ID = cve
	}

	type pkg struct {
		name    string
		version string
	}
	ps := map[pkg][]string{}
	for _, p := range sv.Packages {
		ps[pkg{name: p.Name, version: p.FixedVersion}] = append(ps[pkg{name: p.Name, version: p.FixedVersion}], p.Arch)
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for p, arches := range ps {
		dd.Packages[sv.DefinitionID] = append(dd.Packages[sv.DefinitionID], build.Package{
			Name:    p.name,
			Status:  "fixed",
			Version: [][]build.Version{{{Operator: "lt", Version: p.version}}},
			Arch:    arches,
		})
	}
}
