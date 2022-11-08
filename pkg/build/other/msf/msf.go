package msf

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
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/msf"
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
		srcDir:             filepath.Join(util.SourceDir(), "msf"),
		srcCompressFormat:  "",
		destDir:            filepath.Join(util.DestDir(), "vulnerability"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build Metasploit Framework")
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

		var sv msf.Module
		if err := json.Unmarshal(sbs, &sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		m := build.Metasploit{
			Name:        filepath.Base(sv.Path),
			Title:       sv.Name,
			Description: sv.Description,
			URLs:        []string{fmt.Sprintf("https://github.com/rapid7/metasploit-framework/blob/master%s", sv.Path)},
		}
		var cves []string
		for _, r := range sv.References {
			switch {
			case strings.HasPrefix(r, "CVE-"):
				cves = append(cves, r)
			case strings.HasPrefix(r, "URL-"):
				m.URLs = append(m.URLs, strings.TrimPrefix(r, "URL-"))
			}
		}

		for _, cve := range cves {
			y := strings.Split(cve, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				return nil
			}

			dbs, err := util.Open(util.BuildFilePath(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), options.destCompressFormat)
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.destDir, y, cve))
			}

			var dv build.Vulnerability
			if len(dbs) > 0 {
				if err := json.Unmarshal(dbs, &dv); err != nil {
					return errors.Wrap(err, "unmarshal json")
				}
			}

			fillVulnerability(&dv, cve, &m)

			dbs, err = json.Marshal(dv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", cve)), options.destCompressFormat), dbs, options.destCompressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.destDir, y, cve))
			}
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "walk mitre")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, id string, sv *build.Metasploit) {
	if dv.ID == "" {
		dv.ID = id
	}
	dv.Metasploit = append(dv.Metasploit, *sv)
}
