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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/redhat/oval"
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
		srcDir:             filepath.Join(util.SourceDir(), "redhat", "oval"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "redhat", "oval"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build RedHat OVAL")

	repositoryToCPE := map[string]map[string][]string{}
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

		stream := filepath.Base(filepath.Dir(path))
		v := stream[:1]
		for _, cve := range sv.Advisory.CVEs {
			y := strings.Split(cve.CVEID, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				return nil
			}

			dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve.CVEID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, cve.CVEID))
			}

			var dv build.Vulnerability
			if len(dvbs) > 0 {
				if err := json.Unmarshal(dvbs, &dv); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillVulnerability(&dv, &sv, cve, stream)

			dvbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", cve.CVEID)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, cve.CVEID))
			}

			ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, v, stream, y, fmt.Sprintf("%s.json", cve.CVEID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, stream, y, cve.CVEID))
			}

			var dd build.DetectPackage
			if len(ddbs) > 0 {
				if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillDetect(&dd, cve.CVEID, &sv)

			ddbs, err = json.Marshal(dd)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, v, stream, y, fmt.Sprintf("%s.json", cve.CVEID)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, v, stream, y, cve.CVEID))
			}
		}

		fillRepositoryToCPE(repositoryToCPE, stream, sv.Advisory.CPEs)

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk oval")
	}

	for stream, repoToCPE := range repositoryToCPE {
		v := stream[:1]

		bs, err := json.Marshal(repoToCPE)
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, v, stream, "repository_to_cpe.json"), options.destCompressFormat), bs, options.destCompressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, v, stream, "repository_to_cpe.json"))
		}

		return nil
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *oval.Definition, cve oval.CVE, version string) {
	if dv.ID == "" {
		dv.ID = cve.CVEID
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.RedHatOVAL == nil {
		dv.Advisory.RedHatOVAL = map[string][]build.Advisory{}
	}
	a := build.Advisory{
		ID: sv.DefinitionID,
	}
	lhs, rhs, found := strings.Cut(strings.TrimPrefix(sv.DefinitionID, "oval:com.redhat."), ":def:")
	if !found {
		log.Printf(`[WARN] unexpected DefinitionID format. accepts: "oval:com.redhat.(cve|rhsa|rhba|rhea|unaffected):def:yyyy%%d%%d%%d%%d", received: "%s"`, sv.DefinitionID)
	} else {
		switch lhs {
		case "cve", "unaffected":
			a.URL = fmt.Sprintf("https://access.redhat.com/security/cve/CVE-%s-%s", rhs[0:4], rhs[4:])
		case "rhsa", "rhba", "rhea":
			a.URL = fmt.Sprintf("https://access.redhat.com/errata/%s-%s:%s", strings.ToUpper(lhs), rhs[0:4], rhs[4:])
		default:
			log.Printf(`[WARN] unexpected DefinitionID format. accepts: ["cve", "rhsa", "rhba", "rhea", "unaffected"], received: "%s"`, lhs)
		}
	}
	dv.Advisory.RedHatOVAL[version] = append(dv.Advisory.RedHatOVAL[version], a)

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.RedHatOVAL == nil {
		dv.Title.RedHatOVAL = map[string]map[string]string{}
	}
	if dv.Title.RedHatOVAL[version] == nil {
		dv.Title.RedHatOVAL[version] = map[string]string{}
	}
	dv.Title.RedHatOVAL[version][sv.DefinitionID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.RedHatOVAL == nil {
		dv.Description.RedHatOVAL = map[string]map[string]string{}
	}
	if dv.Description.RedHatOVAL[version] == nil {
		dv.Description.RedHatOVAL[version] = map[string]string{}
	}
	dv.Description.RedHatOVAL[version][sv.DefinitionID] = sv.Description

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.RedHatOVAL == nil {
		dv.CVSS.RedHatOVAL = map[string]map[string][]build.CVSS{}
	}
	if dv.CVSS.RedHatOVAL[version] == nil {
		dv.CVSS.RedHatOVAL[version] = map[string][]build.CVSS{}
	}
	var cvsses []build.CVSS
	if cve.CVSS2 != "" {
		c := build.CVSS{
			Source:   "RedHat",
			Severity: cve.Impact,
		}
		lhs, rhs, found := strings.Cut(cve.CVSS2, "/")
		if found {
			c.Version = "2.0"
			c.Vector = rhs
			if s, err := strconv.ParseFloat(lhs, 64); err == nil {
				c.Score = &s
			} else {
				log.Printf(`[WARN] unexpected CVSS2 Base Score. accepts: float64, received: "%s"`, lhs)
			}
		} else {
			log.Printf(`[WARN] unexpected CVSS2 string. accepts: "<Base Score>/<CVSS2 Vector>", received: "%s"`, cve.CVSS2)
		}
		cvsses = append(cvsses, c)
	}
	if cve.CVSS3 != "" {
		c := build.CVSS{
			Source:   "RedHat",
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
				log.Printf(`[WARN] unexpected CVSS2 Base Score. accepts: float64, received: "%s"`, lhs)
			}
		} else {
			log.Printf(`[WARN] unexpected CVSS3 string. accepts: "<Base Score>/<CVSS3 Vector>", received: "%s"`, cve.CVSS3)
		}
		cvsses = append(cvsses, c)
	}
	if len(cvsses) == 0 && cve.Impact != "" {
		cvsses = append(cvsses, build.CVSS{
			Source:   "RedHat",
			Severity: cve.Impact,
		})
	}
	dv.CVSS.RedHatOVAL[version][sv.DefinitionID] = cvsses

	if cve.CWE != "" {
		if dv.CWE == nil {
			dv.CWE = &build.CWEs{}
		}
		if dv.CWE.RedHatOVAL == nil {
			dv.CWE.RedHatOVAL = map[string]map[string][]string{}
		}
		if dv.CWE.RedHatOVAL[version] == nil {
			dv.CWE.RedHatOVAL[version] = map[string][]string{}
		}
		dv.CWE.RedHatOVAL[version][sv.DefinitionID] = []string{strings.TrimPrefix(cve.CWE, "CWE-")}
	}

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.RedHatOVAL == nil {
		dv.Published.RedHatOVAL = map[string]map[string]*time.Time{}
	}
	if dv.Published.RedHatOVAL[version] == nil {
		dv.Published.RedHatOVAL[version] = map[string]*time.Time{}
	}
	if sv.Advisory.Issued != nil {
		dv.Published.RedHatOVAL[version][sv.DefinitionID] = sv.Advisory.Issued
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if dv.Modified.RedHatOVAL == nil {
		dv.Modified.RedHatOVAL = map[string]map[string]*time.Time{}
	}
	if dv.Modified.RedHatOVAL[version] == nil {
		dv.Modified.RedHatOVAL[version] = map[string]*time.Time{}
	}
	if sv.Advisory.Updated != nil {
		dv.Modified.RedHatOVAL[version][sv.DefinitionID] = sv.Advisory.Updated
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.RedHatOVAL == nil {
		dv.References.RedHatOVAL = map[string]map[string][]build.Reference{}
	}
	if dv.References.RedHatOVAL[version] == nil {
		dv.References.RedHatOVAL[version] = map[string][]build.Reference{}
	}
	for _, b := range sv.Advisory.Bugzillas {
		dv.References.RedHatOVAL[version][sv.DefinitionID] = append(dv.References.RedHatOVAL[version][sv.DefinitionID], build.Reference{
			Source: "BUG",
			Name:   b.Title,
			URL:    b.URL,
		})
	}
	for _, r := range sv.References {
		dv.References.RedHatOVAL[version][sv.DefinitionID] = append(dv.References.RedHatOVAL[version][sv.DefinitionID], build.Reference{
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

	type pkg struct {
		name            string
		status          string
		version         string
		modularitylabel string
	}
	ps := map[pkg][]string{}
	for _, p := range sv.Packages {
		if ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, modularitylabel: p.ModularityLabel}] == nil {
			ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, modularitylabel: p.ModularityLabel}] = []string{}
		}
		if p.Arch != "" {
			ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, modularitylabel: p.ModularityLabel}] = append(ps[pkg{name: p.Name, status: p.Status, version: p.FixedVersion, modularitylabel: p.ModularityLabel}], p.Arch)
		}
	}

	cpes := make([]string, 0, len(sv.Advisory.CPEs))
	for _, c := range sv.Advisory.CPEs {
		cpes = append(cpes, c.CPE)
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for p, arches := range ps {
		v := [][]build.Version{{{Operator: "lt", Version: p.version}}}
		if p.version == "" {
			v = nil
		}
		dd.Packages[sv.DefinitionID] = append(dd.Packages[sv.DefinitionID], build.Package{
			Name:            p.name,
			Status:          p.status,
			Version:         v,
			ModularityLabel: p.modularitylabel,
			Arch:            arches,
			CPE:             cpes,
		})
	}
}

func fillRepositoryToCPE(repositoryToCPE map[string]map[string][]string, version string, cpes []oval.CPE) {
	if repositoryToCPE == nil {
		repositoryToCPE = map[string]map[string][]string{}
	}
	if repositoryToCPE[version] == nil {
		repositoryToCPE[version] = map[string][]string{}
	}
	for _, c := range cpes {
		for _, r := range c.Repository {
			repositoryToCPE[version][r] = util.Unique(append(repositoryToCPE[version][r], c.CPE))
		}
	}
}
