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
		srcDir:             filepath.Join(util.SourceDir(), "debian", "tracker"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "debian", "tracker"),
		destCompressFormat: "",
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

		sbs, err := util.Open(path, options.srcCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}

		var sv tracker.Advisory
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		dir, y := filepath.Split(filepath.Dir(path))
		v := filepath.Base(dir)

		dvbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.ID)), options.destCompressFormat), options.destCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destVulnDir, y, sv.ID))
		}

		var dv build.Vulnerability
		if len(dvbs) > 0 {
			if err := json.Unmarshal(dvbs, &dv); err != nil {
				return errors.Wrap(err, "unmarshal json")
			}
		}

		fillVulnerability(&dv, &sv, v)

		dvbs, err = json.Marshal(dv)
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := util.Write(util.BuildFilePath(filepath.Join(options.destVulnDir, y, fmt.Sprintf("%s.json", sv.ID)), options.destCompressFormat), dvbs, options.destCompressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, y, sv.ID))
		}

		ddbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.ID)), options.destCompressFormat), options.destCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destDetectDir, v, y, sv.ID))
		}

		var dd build.DetectPackage
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

		if err := util.Write(util.BuildFilePath(filepath.Join(options.destDetectDir, v, y, fmt.Sprintf("%s.json", sv.ID)), options.destCompressFormat), ddbs, options.destCompressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.destVulnDir, v, y, sv.ID))
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
