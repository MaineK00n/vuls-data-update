package tracker

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian/tracker"
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
		srcDir:        filepath.Join(util.SourceDir(), "debian", "tracker"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "debian", "tracker"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build Debian Security Tracker")
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

		var sv tracker.Advisory
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		dir, y := filepath.Split(filepath.Dir(path))
		v := filepath.Base(dir)
		if err := os.MkdirAll(filepath.Join(options.destVulnDir, y), os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destVulnDir, y))
		}
		if err := os.MkdirAll(filepath.Join(options.destDetectDir, v, y), os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDetectDir, v, y))
		}

		dvf, err := os.OpenFile(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.ID)), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.ID)))
		}
		defer dvf.Close()

		var dv build.Vulnerability
		if err := json.NewDecoder(dvf).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "decode json")
		}

		fillVulnerability(&dv, &sv, v)

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

		ddf, err := os.OpenFile(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.ID)), os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.ID)))
		}
		defer ddf.Close()

		var dd build.DetectPackage
		if err := json.NewDecoder(ddf).Decode(&dd); err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "decode json")
		}

		fillDetect(&dd, &sv)

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
	}); err != nil {
		return errors.Wrap(err, "walk tracker")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *tracker.Advisory, version string) {
	if dv.ID == "" {
		dv.ID = sv.ID
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	if dv.Advisory.DebianSecurityTracker == nil {
		dv.Advisory.DebianSecurityTracker = map[string]build.Advisory{}
	}
	dv.Advisory.DebianSecurityTracker[version] = build.Advisory{
		ID:  sv.ID,
		URL: fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", sv.ID),
	}

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if dv.Title.DebianSecurityTracker == nil {
		dv.Title.DebianSecurityTracker = map[string]string{}
	}
	dv.Title.DebianSecurityTracker[version] = sv.ID

	if sv.DebianBug != nil {
		if dv.References == nil {
			dv.References = &build.References{}
		}
		if dv.References.DebianSecurityTracker == nil {
			dv.References.DebianSecurityTracker = map[string][]build.Reference{}
		}
		dv.References.DebianSecurityTracker[version] = append(dv.References.DebianSecurityTracker[version], build.Reference{
			Source: "DEBIANBUG",
			Name:   fmt.Sprintf("#%d", *sv.DebianBug),
			URL:    fmt.Sprintf("https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=%d", *sv.DebianBug),
		})
	}
}

func fillDetect(dd *build.DetectPackage, sv *tracker.Advisory) {
	if dd.ID == "" {
		dd.ID = sv.ID
	}

	if dd.Packages == nil {
		dd.Packages = map[string][]build.Package{}
	}
	for _, svp := range sv.Packages {
		p := build.Package{Name: svp.Name}
		switch svp.Status {
		case "resolved":
			p.Status = "not affected"
			if svp.FixedVersion != "0" {
				p.Status = "fixed"
				p.Version = [][]build.Version{{{Operator: "lt", Version: svp.FixedVersion}}}
			}
		case "open", "undetermined":
			p.Status = svp.Status
		default:
			log.Printf(`[WARN] unexpected status. accepts: ["resolved", "open", "undetermined"], received: %s`, svp.Status)
		}
		dd.Packages[sv.ID] = append(dd.Packages[sv.ID], p)
	}
}
