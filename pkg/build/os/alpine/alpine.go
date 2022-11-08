package alpine

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

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/alpine"
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
		srcDir:             filepath.Join(util.SourceDir(), "alpine"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "alpine"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build Alpine Linux")
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

		var sv alpine.Advisory
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, p := range sv.Packages {
			for pkgver, cves := range p.Secfixes {
				for _, cve := range cves {
					for _, id := range strings.Fields(cve) {
						if !strings.HasPrefix(id, "CVE-") {
							continue
						}

						v := strings.TrimPrefix(sv.Distroversion, "v")
						y := strings.Split(id, "-")[1]
						if _, err := strconv.Atoi(y); err != nil {
							log.Printf(`[WARN] unexpected CVE-ID. accepts: "CVE-yyyy-XXXX", received: "%s"`, id)
							continue
						}

						dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), options.destCompressFormat)
						if err != nil {
							return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, id))
						}

						var dv build.Vulnerability
						if len(dvbs) > 0 {
							if err := json.Unmarshal(dvbs, &dv); err != nil {
								return errors.Wrap(err, "unmarshal json")
							}
						}

						fillVulnerability(&dv, id, v)

						dvbs, err = json.Marshal(dv)
						if err != nil {
							return errors.Wrap(err, "marshal json")
						}

						if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
							return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, id))
						}

						ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), options.destCompressFormat)
						if err != nil {
							return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, id))
						}

						var dd build.DetectPackage
						if len(ddbs) > 0 {
							if err := json.Unmarshal(ddbs, &dd); err != nil && !errors.Is(err, io.EOF) {
								return errors.Wrap(err, "unmarshal json")
							}
						}

						fillDetect(&dd, id, p.Name, pkgver, sv.Archs, sv.Reponame)

						ddbs, err = json.Marshal(dd)
						if err != nil {
							return errors.Wrap(err, "marshal json")
						}

						if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", id)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
							return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, v, y, id))
						}
					}
				}
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk alpine")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, cve, version string) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.Alpine == nil {
		dv.Advisory.Alpine = map[string]build.Advisory{}
	}
	dv.Advisory.Alpine[version] = build.Advisory{
		ID:  cve,
		URL: fmt.Sprintf("https://security.alpinelinux.org/vuln/%s", cve),
	}

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.Alpine == nil {
		dv.Title.Alpine = map[string]string{}
	}
	dv.Title.Alpine[version] = cve
}

func fillDetect(dd *build.DetectPackage, cve, name, version string, arches []string, repo string) {
	if dd.ID == "" {
		dd.ID = cve
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	dd.Packages[cve] = append(dd.Packages[cve], build.Package{
		Name:       name,
		Status:     "fixed",
		Version:    [][]build.Version{{{Operator: "lt", Version: version}}},
		Arch:       arches,
		Repository: repo,
	})
}
