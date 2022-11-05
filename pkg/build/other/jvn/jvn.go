package jvn

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/jvn"
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
		srcDir:        filepath.Join(util.SourceDir(), "jvn"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "cpe", "jvn"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build JVN")
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

		var sv jvn.Advisory
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, r := range sv.Related {
			if err := func() error {
				if r.Type != "advisory" || r.Name != "Common Vulnerabilities and Exposures (CVE)" {
					return nil
				}

				y := strings.Split(r.VulinfoID, "-")[1]
				if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
				}

				dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.VulinfoID)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.VulinfoID)))
				}
				defer dvf.Close()

				var dv build.Vulnerability
				if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillVulnerability(&dv, &sv, r.VulinfoID)

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

				if err := os.MkdirAll(filepath.Join(options.destDetectDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, y))
				}

				ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", r.VulinfoID)), os.O_RDWR|os.O_CREATE, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", r.VulinfoID)))
				}
				defer ddf.Close()

				var dd build.DetectCPE
				if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillDetect(&dd, r.VulinfoID, &sv)

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
		return errors.Wrap(err, "walk jvn")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *jvn.Advisory, cve string) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.JVN = append(dv.Advisory.JVN, build.Advisory{
		ID:  sv.VulinfoID,
		URL: fmt.Sprintf("https://jvndb.jvn.jp/ja/contents/%s/%s.html", strings.Split(sv.VulinfoID, "-")[1], sv.VulinfoID),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{JVN: map[string]string{}}
	}
	if dv.Title.JVN == nil {
		dv.Title.JVN = map[string]string{}
	}
	dv.Title.JVN[sv.VulinfoID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{JVN: map[string]string{}}
	}
	if dv.Description.JVN == nil {
		dv.Description.JVN = map[string]string{}
	}
	dv.Description.JVN[sv.VulinfoID] = sv.VulinfoDescription

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if dv.Published.JVN == nil {
		dv.Published.JVN = map[string]*time.Time{}
	}
	if sv.DateFirstPublished != nil {
		dv.Published.JVN[sv.VulinfoID] = sv.DateFirstPublished
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if dv.Modified.JVN == nil {
		dv.Modified.JVN = map[string]*time.Time{}
	}
	if sv.DateLastUpdated != nil {
		dv.Modified.JVN[sv.VulinfoID] = sv.DateLastUpdated
	}

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if dv.CVSS.JVN == nil {
		dv.CVSS.JVN = map[string][]build.CVSS{}
	}
	for _, e := range sv.Impact.Cvss {
		var score *float64
		f, err := strconv.ParseFloat(e.Base, 64)
		if err == nil {
			score = &f
		} else {
			log.Printf(`[WARN] unexpected CVSS BaseScore. accepts: float64, received: %s`, e.Base)
		}

		dv.CVSS.JVN[sv.VulinfoID] = append(dv.CVSS.JVN[sv.VulinfoID], build.CVSS{
			Version:  e.Version,
			Source:   "JVN",
			Vector:   e.Vector,
			Score:    score,
			Severity: e.Severity.Text,
		})
	}

	if dv.CWE == nil {
		dv.CWE = &build.CWEs{}
	}
	if dv.CWE.JVN == nil {
		dv.CWE.JVN = map[string][]string{}
	}
	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.JVN == nil {
		dv.References.JVN = map[string][]build.Reference{}
	}
	for _, r := range sv.Related {
		switch r.Type {
		case "vendor", "advisory":
			dv.References.JVN[sv.VulinfoID] = append(dv.References.JVN[sv.VulinfoID], build.Reference{
				Source: r.Name,
				Name:   r.VulinfoID,
				URL:    r.URL,
			})
		case "cwe":
			dv.CWE.JVN[sv.VulinfoID] = append(dv.CWE.JVN[sv.VulinfoID], strings.TrimPrefix(r.VulinfoID, "CWE-"))
		}
	}
}

func fillDetect(dd *build.DetectCPE, cve string, sv *jvn.Advisory) {
	if dd.ID == "" {
		dd.ID = cve
	}

	var cs []build.CPE
	for _, a := range sv.Affected {
		if a.CPE == nil {
			continue
		}
		cs = append(cs, build.CPE{
			CPEVersion: a.CPE.Version,
			CPE:        a.CPE.Text,
		})
	}
	if len(cs) == 0 {
		return
	}
	if dd.Configurations == nil {
		dd.Configurations = map[string][]build.CPEConfiguration{}
	}
	dd.Configurations[sv.VulinfoID] = []build.CPEConfiguration{{Vulnerable: cs}}
}
