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
		srcDir:        filepath.Join(util.SourceDir(), "redhat", "oval"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "redhat", "oval"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	// stream: repository: cpe
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

		sf, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer sf.Close()

		var sv oval.Definition
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		stream := filepath.Base(filepath.Dir(path))
		v := stream[:1]
		for _, cve := range sv.Advisory.CVEs {
			if err := func() error {
				y := strings.Split(cve.CVEID, "-")[1]
				if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
				}
				if err := os.MkdirAll(filepath.Join(options.destDetectDir, v, stream, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, v, stream, y))
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

				fillVulnerability(&dv, &sv, cve, stream)

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

				ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, v, stream, y, fmt.Sprintf("%s.json", cve.CVEID)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, stream, y, fmt.Sprintf("%s.json", cve.CVEID)))
				}
				defer ddf.Close()

				var dd build.DetectPackage
				if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillDetect(&dd, cve.CVEID, &sv)

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

		fillRepositoryToCPE(repositoryToCPE, stream, sv.Advisory.CPEs)

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk oval")
	}

	for stream, repoToCPE := range repositoryToCPE {
		if err := func() error {
			v := stream[:1]
			if err := os.MkdirAll(filepath.Join(options.destDetectDir, v, stream), os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, v, stream))
			}

			f, err := os.Create(filepath.Join(options.destDetectDir, v, stream, "repository_to_cpe.json"))
			if err != nil {
				return errors.Wrapf(err, "create %s", filepath.Join(options.destDetectDir, v, stream, "repository_to_cpe.json"))
			}
			defer f.Close()

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(repoToCPE); err != nil {
				return errors.Wrap(err, "encode json")
			}

			return nil
		}(); err != nil {
			return err
		}
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
	if dv.Advisory.RedHat == nil {
		dv.Advisory.RedHat = map[string][]build.Advisory{}
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
	dv.Advisory.RedHat[version] = append(dv.Advisory.RedHat[version], a)

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.RedHat == nil {
		dv.Title.RedHat = map[string]map[string]string{}
	}
	if dv.Title.RedHat[version] == nil {
		dv.Title.RedHat[version] = map[string]string{}
	}
	dv.Title.RedHat[version][sv.DefinitionID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.RedHat == nil {
		dv.Description.RedHat = map[string]map[string]string{}
	}
	if dv.Description.RedHat[version] == nil {
		dv.Description.RedHat[version] = map[string]string{}
	}
	dv.Description.RedHat[version][sv.DefinitionID] = sv.Description

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.RedHat == nil {
		dv.CVSS.RedHat = map[string]map[string][]build.CVSS{}
	}
	if dv.CVSS.RedHat[version] == nil {
		dv.CVSS.RedHat[version] = map[string][]build.CVSS{}
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
	dv.CVSS.RedHat[version][sv.DefinitionID] = cvsses

	if cve.CWE != "" {
		if dv.CWE == nil {
			dv.CWE = &build.CWEs{}
		}
		if dv.CWE.RedHat == nil {
			dv.CWE.RedHat = map[string]map[string][]string{}
		}
		if dv.CWE.RedHat[version] == nil {
			dv.CWE.RedHat[version] = map[string][]string{}
		}
		dv.CWE.RedHat[version][sv.DefinitionID] = []string{strings.TrimPrefix(cve.CWE, "CWE-")}
	}

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.RedHat == nil {
		dv.Published.RedHat = map[string]map[string]*time.Time{}
	}
	if dv.Published.RedHat[version] == nil {
		dv.Published.RedHat[version] = map[string]*time.Time{}
	}
	if sv.Advisory.Issued != nil {
		dv.Published.RedHat[version][sv.DefinitionID] = sv.Advisory.Issued
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if dv.Modified.RedHat == nil {
		dv.Modified.RedHat = map[string]map[string]*time.Time{}
	}
	if dv.Modified.RedHat[version] == nil {
		dv.Modified.RedHat[version] = map[string]*time.Time{}
	}
	if sv.Advisory.Updated != nil {
		dv.Modified.RedHat[version][sv.DefinitionID] = sv.Advisory.Updated
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.RedHat == nil {
		dv.References.RedHat = map[string]map[string][]build.Reference{}
	}
	if dv.References.RedHat[version] == nil {
		dv.References.RedHat[version] = map[string][]build.Reference{}
	}
	for _, b := range sv.Advisory.Bugzillas {
		dv.References.RedHat[version][sv.DefinitionID] = append(dv.References.RedHat[version][sv.DefinitionID], build.Reference{
			Source: "RHBUG",
			Name:   b.Title,
			URL:    b.URL,
		})
	}
	for _, r := range sv.References {
		dv.References.RedHat[version][sv.DefinitionID] = append(dv.References.RedHat[version][sv.DefinitionID], build.Reference{
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
