package nvd

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

	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/nvd"
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
		srcDir:             filepath.Join(util.SourceDir(), "nvd"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "cpe", "nvd"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build NVD")
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

		switch {
		case strings.HasPrefix(filepath.Base(path), "cpe-dictionary.json"):
		default:
			sbs, err := util.Open(path, options.srcCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", path)
			}

			var sv nvd.CVEItem
			if err := json.Unmarshal(sbs, &sv); err != nil {
				return errors.Wrap(err, "decode json")
			}

			y := strings.Split(sv.Cve.CVEDataMeta.ID, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				log.Printf(`[WARN] unexpected CVE-ID. accepts: "CVE-yyyy-XXXX", received: "%s"`, sv.Cve.CVEDataMeta.ID)
				return nil
			}

			dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Cve.CVEDataMeta.ID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, sv.Cve.CVEDataMeta.ID))
			}

			var dv build.Vulnerability
			if len(dvbs) > 0 {
				if err := json.Unmarshal(dvbs, &dv); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillVulnerability(&dv, &sv)

			dvbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.Cve.CVEDataMeta.ID)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, sv.Cve.CVEDataMeta.ID))
			}

			ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", sv.Cve.CVEDataMeta.ID)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, y, sv.Cve.CVEDataMeta.ID))
			}

			var dd build.DetectCPE
			if len(ddbs) > 0 {
				if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillDetect(&dd, &sv)

			ddbs, err = json.Marshal(dd)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, y, fmt.Sprintf("%s.json", sv.Cve.CVEDataMeta.ID)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, sv.Cve.CVEDataMeta.ID))
			}
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "walk nvd")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *nvd.CVEItem) {
	if dv.ID == "" {
		dv.ID = sv.Cve.CVEDataMeta.ID
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.NVD = &build.Advisory{
		ID:  sv.Cve.CVEDataMeta.ID,
		URL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", sv.Cve.CVEDataMeta.ID),
	}

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	dv.Title.NVD = sv.Cve.CVEDataMeta.ID

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	for _, d := range sv.Cve.Description.DescriptionData {
		if d.Lang == "en" {
			dv.Description.NVD = d.Value
		}
	}

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if sv.PublishedDate != nil {
		dv.Published.NVD = sv.PublishedDate
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if sv.LastModifiedDate != nil {
		dv.Modified.NVD = sv.LastModifiedDate
	}

	if dv.CVSS == nil {
		dv.CVSS = &build.CVSSes{}
	}
	if sv.Impact.BaseMetricV2 != nil {
		dv.CVSS.NVD = append(dv.CVSS.NVD, build.CVSS{
			Version:  sv.Impact.BaseMetricV2.CvssV2.Version,
			Source:   "NIST",
			Vector:   sv.Impact.BaseMetricV2.CvssV2.VectorString,
			Score:    &sv.Impact.BaseMetricV2.CvssV2.BaseScore,
			Severity: sv.Impact.BaseMetricV2.Severity,
		})
	}

	if sv.Impact.BaseMetricV3 != nil {
		dv.CVSS.NVD = append(dv.CVSS.NVD, build.CVSS{
			Version:  sv.Impact.BaseMetricV3.CvssV3.Version,
			Source:   "NIST",
			Vector:   sv.Impact.BaseMetricV3.CvssV3.VectorString,
			Score:    &sv.Impact.BaseMetricV3.CvssV3.BaseScore,
			Severity: sv.Impact.BaseMetricV3.CvssV3.BaseSeverity,
		})
	}

	if dv.CWE == nil {
		dv.CWE = &build.CWEs{}
	}
	for _, p := range sv.Cve.Problemtype.ProblemtypeData {
		for _, d := range p.Description {
			if d.Lang == "en" {
				dv.CWE.NVD = append(dv.CWE.NVD, strings.TrimPrefix(strings.TrimPrefix(d.Value, "NVD-"), "CWE-"))
			}
		}
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	for _, r := range sv.Cve.References.ReferenceData {
		dv.References.NVD = append(dv.References.NVD, build.Reference{
			Source: r.Refsource,
			Name:   r.Name,
			Tags:   r.Tags,
			URL:    r.URL,
		})

		if slices.Contains(r.Tags, "Exploit") {
			if dv.Exploit == nil {
				dv.Exploit = &build.Exploit{}
			}
			dv.Exploit.NVD = append(dv.Exploit.NVD, r.URL)
		}

		if slices.Contains(r.Tags, "Mitigation") {
			if dv.Mitigation == nil {
				dv.Mitigation = &build.Mitigation{}
			}
			dv.Mitigation.NVD = append(dv.Mitigation.NVD, r.URL)
		}
	}
}

func fillDetect(dd *build.DetectCPE, sv *nvd.CVEItem) {
	if dd.ID == "" {
		dd.ID = sv.Cve.CVEDataMeta.ID
	}

	for _, n := range sv.Configurations.Nodes {
		var configuration build.CPEConfiguration
		switch n.Operator {
		case "AND":
			for _, child := range n.Children {
				for _, c := range child.CpeMatch {
					var vs []build.Version
					if c.VersionEndExcluding != nil {
						vs = append(vs, build.Version{Operator: "lt", Version: *c.VersionEndExcluding})
					}
					if c.VersionEndIncluding != nil {
						vs = append(vs, build.Version{Operator: "le", Version: *c.VersionEndIncluding})
					}
					if c.VersionStartExcluding != nil {
						vs = append(vs, build.Version{Operator: "gt", Version: *c.VersionStartExcluding})
					}
					if c.VersionStartIncluding != nil {
						vs = append(vs, build.Version{Operator: "ge", Version: *c.VersionStartIncluding})
					}

					if c.Vulnerable {
						configuration.Vulnerable = append(configuration.Vulnerable, build.CPE{
							CPEVersion: "2.3",
							CPE:        c.Cpe23URI,
							Version:    vs,
						})
					} else {
						configuration.RunningOn = append(configuration.RunningOn, build.CPE{
							CPEVersion: "2.3",
							CPE:        c.Cpe23URI,
							Version:    vs,
						})
					}
				}
			}
		case "OR":
			for _, c := range n.CpeMatch {
				if !c.Vulnerable {
					continue
				}

				var vs []build.Version
				if c.VersionEndExcluding != nil {
					vs = append(vs, build.Version{Operator: "lt", Version: *c.VersionEndExcluding})
				}
				if c.VersionEndIncluding != nil {
					vs = append(vs, build.Version{Operator: "le", Version: *c.VersionEndIncluding})
				}
				if c.VersionStartExcluding != nil {
					vs = append(vs, build.Version{Operator: "gt", Version: *c.VersionStartExcluding})
				}
				if c.VersionStartIncluding != nil {
					vs = append(vs, build.Version{Operator: "ge", Version: *c.VersionStartIncluding})
				}
				configuration.Vulnerable = append(configuration.Vulnerable, build.CPE{
					CPEVersion: "2.3",
					CPE:        c.Cpe23URI,
					Version:    vs,
				})
			}
		}

		if len(configuration.Vulnerable) == 0 {
			continue
		}
		if dd.Configurations == nil {
			dd.Configurations = map[string][]build.CPEConfiguration{}
		}
		dd.Configurations[sv.Cve.CVEDataMeta.ID] = append(dd.Configurations[sv.Cve.CVEDataMeta.ID], configuration)
	}
}
