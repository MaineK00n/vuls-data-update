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
		srcDir:        filepath.Join(util.SourceDir(), "alpine"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "alpine"),
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

		sf, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer sf.Close()

		var sv alpine.Advisory
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, p := range sv.Packages {
			for v, cves := range p.Secfixes {
				for _, cve := range cves {
					for _, id := range strings.Fields(cve) {
						if !strings.HasPrefix(id, "CVE-") {
							continue
						}

						y := strings.Split(id, "-")[1]
						if _, err := strconv.Atoi(y); err != nil {
							continue
						}
						if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
							return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
						}
						if err := os.MkdirAll(filepath.Join(options.destDetectDir, strings.TrimPrefix(sv.Distroversion, "v"), y), os.ModePerm); err != nil {
							return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, strings.TrimPrefix(sv.Distroversion, "v"), y))
						}

						dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)), os.O_RDWR|os.O_CREATE, 0644)
						if err != nil {
							return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", id)))
						}
						defer dvf.Close()

						var dv build.Vulnerability
						if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
							return errors.Wrap(err, "decode json")
						}

						fillVulnerability(&dv, id, strings.TrimPrefix(sv.Distroversion, "v"))

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

						ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, strings.TrimPrefix(sv.Distroversion, "v"), y, fmt.Sprintf("%s.json", id)), os.O_RDWR|os.O_CREATE, 0644)
						if err != nil {
							return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, strings.TrimPrefix(sv.Distroversion, "v"), y, fmt.Sprintf("%s.json", id)))
						}
						defer ddf.Close()

						var dd build.DetectPackage
						if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
							return errors.Wrap(err, "decode json")
						}

						fillDetect(&dd, id, p.Name, v, sv.Archs, sv.Reponame)

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
		Name:         name,
		Status:       "fixed",
		FixedVersion: version,
		Arch:         arches,
		Repository:   repo,
	})
}
