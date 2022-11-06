package msf

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/msf"
)

type options struct {
	srcDir  string
	destDir string
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

type destDirOption string

func (d destDirOption) apply(opts *options) {
	opts.destDir = string(d)
}

func WithDestDir(dir string) Option {
	return destDirOption(dir)
}

func Build(opts ...Option) error {
	options := &options{
		srcDir:  filepath.Join(util.SourceDir(), "msf"),
		destDir: filepath.Join(util.DestDir(), "vulnerability"),
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

		sf, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer sf.Close()

		var sv msf.Module
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
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
			if err := func() error {
				y := strings.Split(cve, "-")[1]
				if err := os.MkdirAll(filepath.Join(options.destDir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDir, y))
				}

				df, err := os.OpenFile(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", cve)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
				if err != nil {
					return errors.Wrapf(err, "open %s", filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", cve)))
				}
				defer df.Close()

				var dv build.Vulnerability
				if err := json.NewDecoder(df).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
					return errors.Wrap(err, "decode json")
				}

				fillVulnerability(&dv, &m, cve)

				if err := df.Truncate(0); err != nil {
					return errors.Wrap(err, "truncate file")
				}
				if _, err := df.Seek(0, 0); err != nil {
					return errors.Wrap(err, "set offset")
				}
				enc := json.NewEncoder(df)
				enc.SetIndent("", "  ")
				if err := enc.Encode(dv); err != nil {
					return errors.Wrap(err, "encode json")
				}

				return nil
			}(); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "walk mitre")
	}

	return nil
}

func fillVulnerability(dv *build.Vulnerability, sv *build.Metasploit, id string) {
	if dv.ID == "" {
		dv.ID = id
	}
	dv.Metasploit = append(dv.Metasploit, *sv)
}
