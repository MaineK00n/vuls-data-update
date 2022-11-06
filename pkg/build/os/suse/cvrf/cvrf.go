package cvrf

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

	"github.com/knqyf263/go-version"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/suse/cvrf"
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
		srcDir:        filepath.Join(util.SourceDir(), "suse", "cvrf"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "suse", "cvrf"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build SUSE CVRF")
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

		var sv cvrf.CVRF
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		y := strings.Split(sv.Vulnerability.CVE, "-")[1]
		if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
		}

		dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Vulnerability.CVE)), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Vulnerability.CVE)))
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

		productToFamily := map[string][]string{}
		for _, b := range sv.ProductTree.Branch {
			if b.Type != "Product Family" {
				continue
			}
			for _, bb := range b.Branch {
				if bb.Type != "Product Name" {
					continue
				}
				productToFamily[bb.Name] = append(productToFamily[bb.Name], b.Name)
			}
		}

		productIDToStatus := map[string]string{}
		for _, s := range sv.Vulnerability.ProductStatuses {
			for _, p := range s.ProductID {
				productIDToStatus[p] = s.Type
			}
		}

		ospkgs := map[string]map[string][]build.Package{}
		for _, r := range sv.ProductTree.Relationship {
			fs, ok := productToFamily[r.RelatesToProductReference]
			if !ok {
				return errors.Errorf("no family found for product: %s. %s Product Tree Relation may be broken.", r.RelatesToProductReference, sv.DocumentTitle)
			}
			status, ok := productIDToStatus[fmt.Sprintf("%s:%s", r.RelatesToProductReference, r.ProductReference)]
			if !ok {
				return errors.Errorf("no status found for productID: %s. %s Product Tree and Product Statuses Relation may be broken.", fmt.Sprintf("%s:%s", r.RelatesToProductReference, r.ProductReference), sv.DocumentTitle)
			}
			p, err := getPackage(r.ProductReference, status)
			if err != nil {
				return errors.Wrap(err, "get package")
			}
			for _, f := range fs {
				name, ver, err := getOS(f)
				if err != nil {
					return errors.Wrap(err, "get os")
				}
				if name == "" || ver == "" {
					continue
				}
				if ospkgs[name] == nil {
					ospkgs[name] = map[string][]build.Package{}
				}
				ospkgs[name][ver] = append(ospkgs[name][ver], p)
			}
		}

		for family, verpkgs := range ospkgs {
			for v, pkgs := range verpkgs {
				if err := func() error {
					if err := os.MkdirAll(filepath.Join(options.destDetectDir, family, v, y), os.ModePerm); err != nil {
						return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, family, v, y))
					}

					ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, family, v, y, fmt.Sprintf("%s.json", sv.Vulnerability.CVE)), os.O_RDWR|os.O_CREATE, 0644)
					if err != nil {
						return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, family, v, y, fmt.Sprintf("%s.json", sv.Vulnerability.CVE)))
					}
					defer ddf.Close()

					var dd build.DetectPackage
					if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
						return errors.Wrap(err, "decode json")
					}

					fillDetect(&dd, sv.Vulnerability.CVE, pkgs)

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
		return errors.Wrap(err, "walk cvrf")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *cvrf.CVRF) {
	if dv.ID == "" {
		dv.ID = sv.Vulnerability.CVE
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.SUSECVRF = &build.Advisory{
		ID:  sv.Vulnerability.CVE,
		URL: fmt.Sprintf("https://ftp.suse.com/pub/projects/security/cvrf-cve/cvrf-%s.xml", sv.Vulnerability.CVE),
	}

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	dv.Title.SUSECVRF = sv.Vulnerability.CVE

	for _, n := range sv.Vulnerability.Notes {
		if n.Title != "Vulnerability Descritption" {
			continue
		}
		if dv.Description == nil {
			dv.Description = &build.Descriptions{}
		}
		dv.Description.SUSECVRF = n.Text
		break
	}

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	var cvsses []build.CVSS
	var impact string
	for _, t := range sv.Vulnerability.Threats {
		if t.Type != "Impact" {
			continue
		}
		impact = t.Description
		break
	}
	if sv.Vulnerability.CVSSScoreSets.ScoreSetV2.BaseScoreV2 != "" || sv.Vulnerability.CVSSScoreSets.ScoreSetV2.VectorV2 != "" {
		c := build.CVSS{
			Version: "2.0",
			Source:  "SUSE",
			Vector:  sv.Vulnerability.CVSSScoreSets.ScoreSetV2.VectorV2,
		}
		if sv.Vulnerability.CVSSScoreSets.ScoreSetV2.BaseScoreV2 != "" {
			if f, err := strconv.ParseFloat(sv.Vulnerability.CVSSScoreSets.ScoreSetV2.BaseScoreV2, 64); err == nil {
				c.Score = &f
			} else {
				log.Printf(`[WARN] unexpected CVSS2 Base Score. accepts: float64, received: "%s"`, sv.Vulnerability.CVSSScoreSets.ScoreSetV2.BaseScoreV2)
			}
		}
		cvsses = append(cvsses, c)
	}
	if sv.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3 != "" || sv.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3 != "" {
		c := build.CVSS{
			Version: "3.0",
			Source:  "SUSE",
			Vector:  sv.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3,
		}
		if strings.HasPrefix(sv.Vulnerability.CVSSScoreSets.ScoreSetV3.VectorV3, "CVSS:3.1") {
			c.Version = "3.1"
		}
		if sv.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3 != "" {
			if f, err := strconv.ParseFloat(sv.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3, 64); err == nil {
				c.Score = &f
			} else {
				log.Printf(`[WARN] unexpected CVSS3 Base Score. accepts: float64, received: "%s"`, sv.Vulnerability.CVSSScoreSets.ScoreSetV3.BaseScoreV3)
			}
		}
		cvsses = append(cvsses, c)
	}
	if len(cvsses) == 0 && impact != "" {
		cvsses = append(cvsses, build.CVSS{
			Source:   "SUSE",
			Severity: impact,
		})
	}
	dv.CVSS.SUSECVRF = cvsses

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	dv.Published.SUSECVRF = sv.DocumentTracking.InitialReleaseDate

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	dv.Modified.SUSECVRF = sv.DocumentTracking.CurrentReleaseDate

	if dv.References == nil {
		dv.References = &build.References{}
	}
	for _, r := range sv.DocumentReferences {
		dv.References.SUSECVRF = append(dv.References.SUSECVRF, build.Reference{
			Source: "SUSE",
			Name:   r.Description,
			URL:    r.URL,
		})
	}
}

func getOS(platform string) (string, string, error) {
	if strings.HasPrefix(platform, "openSUSE") {
		if strings.HasPrefix(platform, "openSUSE Leap") {
			// e.g. openSUSE Leap 15.0, openSUSE Leap 15.0 NonFree, openSUSE Leap Micro 5.2
			if strings.HasPrefix(platform, "openSUSE Leap Micro") {
				return "", "", nil
			}

			ss := strings.Fields(platform)
			if len(ss) < 3 {
				return "", "", errors.Errorf(`unexpected version string. expected: "openSUSE Leap <Version>", actual: "%s"`, platform)
			}
			if _, err := version.NewVersion(ss[2]); err != nil {
				return "", "", errors.Wrap(err, "parse version")
			}
			return "opensuse.leap", ss[2], nil
		}

		// e.g. openSUSE 13.2, openSUSE Tumbleweed
		ss := strings.Fields(platform)
		if len(ss) < 2 {
			return "", "", errors.Errorf(`unexpected version string. expected: "openSUSE <Version>", actual: "%s"`, platform)
		}
		if ss[1] == "Tumbleweed" {
			return "opensuse", "tumbleweed", nil
		}
		if _, err := version.NewVersion(ss[1]); err != nil {
			return "", "", errors.Wrap(err, "parse version")
		}
		return "opensuse", ss[1], nil
	}

	if strings.HasPrefix(platform, "SUSE Linux Enterprise") {
		var osname string
		switch {
		case strings.HasPrefix(platform, "SUSE Linux Enterprise Desktop"):
			osname = "suse.linux.enterprise.desktop"
		case strings.HasPrefix(platform, "SUSE Linux Enterprise Server"):
			osname = "suse.linux.enterprise.server"
		default:
			return "", "", nil
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
			return "", "", errors.Errorf(`unexpected version string. expected: "SUSE Linux Enterprise ... <Major Version>(-SP<MINOR Version>)", actual: "%s"`, platform)
		case 1:
			if _, err := version.NewVersion(vs[0]); err != nil {
				return "", "", errors.Wrap(err, "parse version")
			}
			return osname, vs[0], nil
		case 2:
			if _, err := version.NewVersion(vs[1]); err != nil {
				return "", "", errors.Wrap(err, "parse major version")
			}
			if _, err := version.NewVersion(vs[0]); err != nil {
				return "", "", errors.Wrap(err, "parse minor version")
			}
			return osname, fmt.Sprintf("%s.%s", vs[1], vs[0]), nil
		}

		return "", "", errors.Errorf(`unexpected version string. expected: "SUSE Linux Enterprise .+ <Major Version>.*( SP\d.*)?", actual: "%s"`, platform)
	}

	return "", "", nil
}

func getPackage(pkg, status string) (build.Package, error) {
	switch status {
	case "Fixed", "First Fixed":
		// get release index
		index := strings.LastIndex(pkg, "-")
		if index == -1 {
			return build.Package{}, errors.Errorf(`unexpected package string. accepts: "<package name>-<version>-<release>", received: "%s"`, pkg)
		}

		// get version index
		index = strings.LastIndex(pkg, "-")
		if index == -1 {
			return build.Package{}, errors.Errorf(`unexpected package string. accepts: "<package name>-<version>-<release>", received: "%s"`, pkg)
		}

		return build.Package{
			Name:    pkg[:index],
			Status:  status,
			Version: [][]build.Version{{{Operator: "lt", Version: pkg[index+1:]}}},
		}, nil
	case "Known Affected", "Known Not Affected":
		return build.Package{Name: pkg, Status: status}, nil
	default:
		return build.Package{}, errors.Errorf(`unexpected status. accepts: ["Fixed", "First Fixed", "Known Affected", "Known Not Affected"], received: "%s"`, status)
	}
}

func fillDetect(dd *build.DetectPackage, cve string, pkgs []build.Package) {
	if dd.ID == "" {
		dd.ID = cve
	}

	type pkg struct {
		name    string
		status  string
		version string
	}
	ps := map[pkg]struct{}{}

	for _, p := range pkgs {
		k := pkg{name: p.Name, status: p.Status}
		if len(p.Version) == 1 {
			k.version = p.Version[0][0].Version
		}
		ps[k] = struct{}{}
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for p := range ps {
		bp := build.Package{
			Name:   p.name,
			Status: p.status,
		}
		if p.version != "" {
			bp.Version = [][]build.Version{{{Operator: "lt", Version: p.version}}}
		}
		dd.Packages[cve] = append(dd.Packages[cve], bp)
	}
}
