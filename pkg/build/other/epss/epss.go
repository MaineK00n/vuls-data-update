package epss

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/epss"
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
		srcDir:             filepath.Join(util.SourceDir(), "epss"),
		srcCompressFormat:  "",
		destDir:            filepath.Join(util.DestDir(), "vulnerability"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build Exploit Prediction Scoring System: EPSS")
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

		var sv epss.EPSS
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		y := strings.Split(sv.ID, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			return nil
		}

		dbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", sv.ID)), options.destCompressFormat), options.destCompressFormat)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destDir, y, sv.ID))
		}

		var dv build.Vulnerability
		if len(dbs) > 0 {
			if err := json.Unmarshal(dbs, &dv); err != nil {
				return errors.Wrap(err, "unmarshal json")
			}
		}

		fillVulnerability(&dv, &sv)

		if err := util.Write(util.BuildFilePath(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", sv.ID)), options.destCompressFormat), dbs, options.destCompressFormat); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.destDir, y, sv.ID))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk epss")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *epss.EPSS) {
	if dv.ID == "" {
		dv.ID = sv.ID
	}
	dv.EPSS = &build.EPSS{EPSS: &sv.EPSS, Percentile: &sv.Percentile}
}
