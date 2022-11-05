package oval

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian/oval"
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
		srcDir:        filepath.Join(util.SourceDir(), "debian", "oval"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "debian", "oval"),
	}

	for _, o := range opts {
		o.apply(options)
	}

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

		for _, r := range sv.References {
			if r.Source != "CVE" {
				continue
			}

			v := filepath.Base(filepath.Dir(path))
			y := strings.Split(r.ID, "-")[1]
			if strings.HasPrefix(r.ID, "TEMP-") {
				y = "TEMP"
			}
			if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
			}
			if err := os.MkdirAll(filepath.Join(options.destDetectDir, v, y), os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, v, y))
			}

			dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.ID)), os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", r.ID)))
			}
			defer dvf.Close()

			var dv build.Vulnerability
			if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
				return errors.Wrap(err, "decode json")
			}

			fillVulnerability(&dv, &sv, r.ID, v)

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

			ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", r.ID)), os.O_RDWR|os.O_CREATE, 0644)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", r.ID)))
			}
			defer ddf.Close()

			var dd build.DetectPackage
			if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
				return errors.Wrap(err, "decode json")
			}

			fillDetect(&dd, &sv, r.ID)

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

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk oval")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *oval.Definition, cve, version string) {
	if dv.ID == "" {
		dv.ID = cve
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.DebianOVAL == nil {
		dv.Advisory.DebianOVAL = map[string][]build.Advisory{}
	}
	dv.Advisory.DebianOVAL[version] = append(dv.Advisory.DebianOVAL[version], build.Advisory{
		ID:  sv.DefinitionID,
		URL: fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", strings.Fields(sv.Title)[0]),
	})

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.DebianOVAL == nil {
		dv.Title.DebianOVAL = map[string]map[string]string{}
	}
	if dv.Title.DebianOVAL[version] == nil {
		dv.Title.DebianOVAL[version] = map[string]string{}
	}
	dv.Title.DebianOVAL[version][sv.DefinitionID] = sv.Title

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if dv.Description.DebianOVAL == nil {
		dv.Description.DebianOVAL = map[string]map[string]string{}
	}
	if dv.Description.DebianOVAL[version] == nil {
		dv.Description.DebianOVAL[version] = map[string]string{}
	}
	dv.Description.DebianOVAL[version][sv.DefinitionID] = sv.Description
	if strings.HasPrefix(sv.Title, "DSA-") && sv.Debian.MoreInfo != "" {
		dv.Description.DebianOVAL[version][sv.DefinitionID] = sv.Debian.MoreInfo
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	if dv.References.DebianOVAL == nil {
		dv.References.DebianOVAL = map[string]map[string][]build.Reference{}
	}
	if dv.References.DebianOVAL[version] == nil {
		dv.References.DebianOVAL[version] = map[string][]build.Reference{}
	}
	for _, r := range sv.References {
		dv.References.DebianOVAL[version][sv.DefinitionID] = append(dv.References.DebianOVAL[version][sv.DefinitionID], build.Reference{
			Source: r.Source,
			Name:   r.ID,
			URL:    r.URL,
		})
	}
}

func fillDetect(dd *build.DetectPackage, sv *oval.Definition, cve string) {
	if dd.ID == "" {
		dd.ID = cve
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	switch sv.Package.FixedVersion {
	case "0:0":
		dd.Packages[sv.DefinitionID] = []build.Package{
			{
				Name:   sv.Package.Name,
				Status: "vulnerable",
			},
		}
	default:
		dd.Packages[sv.DefinitionID] = []build.Package{
			{
				Name:    sv.Package.Name,
				Status:  "fixed",
				Version: [][]build.Version{{{Operator: "lt", Version: sv.Package.FixedVersion}}},
			},
		}
	}
}
