package mitre

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/mitre"
)

type options struct {
	srcDir             string
	srcCompressFormat  string
	destDir            string
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

type destDirOption string

func (d destDirOption) apply(opts *options) {
	opts.destDir = string(d)
}

func WithDestDir(dir string) Option {
	return destDirOption(dir)
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
		srcDir:             filepath.Join(util.SourceDir(), "mitre"),
		srcCompressFormat:  "",
		destDir:            filepath.Join(util.DestDir(), "vulnerability"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build MITRE CVE List")
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

		var sv mitre.Vulnerability
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		y := strings.Split(sv.CVE, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			log.Printf(`[WARN] unexpected CVE-ID. accepts: "CVE-yyyy-XXXX", received: "%s"`, sv.CVE)
			return nil
		}

		dbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", sv.CVE)), options.destCompressFormat), options.destCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destDir, y, sv.CVE))
		}

		var dv build.Vulnerability
		if len(dbs) > 0 {
			if err := json.Unmarshal(dbs, &dv); err != nil {
				return errors.Wrap(err, "unmarshal json")
			}
		}

		fillVulnerability(&dv, &sv)

		dbs, err = json.Marshal(dv)
		if err != nil {
			return errors.Wrap(err, "marshal json")
		}

		if err := util.Write(util.BuildFilePath(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", sv.CVE)), options.destCompressFormat), dbs, options.destCompressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.destDir, y, sv.CVE))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk mitre")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *mitre.Vulnerability) {
	if dv.ID == "" {
		dv.ID = sv.CVE
	}

	if dv.Advisory == nil {
		dv.Advisory = &build.Advisories{}
	}
	dv.Advisory.MITRE = &build.Advisory{
		ID:  sv.CVE,
		URL: fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", sv.CVE),
	}

	if dv.Title == nil {
		dv.Title = &build.Titles{}
	}
	if sv.Title != "" {
		dv.Title.MITRE = sv.Title
	}

	if dv.Description == nil {
		dv.Description = &build.Descriptions{}
	}
	if sv.Notes.Description != "" {
		dv.Description.MITRE = sv.Notes.Description
	}

	if dv.Published == nil {
		dv.Published = &build.Publisheds{}
	}
	if sv.Notes.Published != nil {
		dv.Published.MITRE = sv.Notes.Published
	}

	if dv.Modified == nil {
		dv.Modified = &build.Modifieds{}
	}
	if sv.Notes.Modified != nil {
		dv.Modified.MITRE = sv.Notes.Modified
	}

	if dv.References == nil {
		dv.References = &build.References{}
	}
	for _, r := range sv.References {
		lhs, rhs, found := strings.Cut(r.Description, ":")
		if !found {
			rhs = lhs
		}
		dv.References.MITRE = append(dv.References.MITRE, build.Reference{
			Source: lhs,
			Name:   rhs,
			URL:    r.URL,
		})
	}
}
