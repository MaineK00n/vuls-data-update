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
		srcDir:             filepath.Join(util.SourceDir(), "jvn"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "cpe", "jvn"),
		destCompressFormat: "",
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

		sbs, err := util.Open(path, options.srcCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}

		var sv jvn.Advisory
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, r := range sv.Related {
			if r.Type != "advisory" || r.Name != "Common Vulnerabilities and Exposures (CVE)" {
				continue
			}

			y := strings.Split(r.VulinfoID, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				log.Printf(`[WARN] unexpected CVE-ID. accepts: "CVE-yyyy-XXXX", received: "%s"`, r.VulinfoID)
				continue
			}

			dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.VulinfoID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, r.VulinfoID))
			}

			var dv build.Vulnerability
			if len(dvbs) > 0 {
				if err := json.Unmarshal(dvbs, &dv); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillVulnerability(&dv, &sv, r.VulinfoID)

			dvbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.VulinfoID)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, r.VulinfoID))
			}

			ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", r.VulinfoID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, y, r.VulinfoID))
			}

			var dd build.DetectCPE
			if len(ddbs) > 0 {
				if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillDetect(&dd, r.VulinfoID, &sv)

			ddbs, err = json.Marshal(dd)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", r.VulinfoID)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, r.VulinfoID))
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
