package mitre

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/mitre"
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
		srcDir:  filepath.Join(util.SourceDir(), "mitre"),
		destDir: filepath.Join(util.DestDir(), "vulnerability"),
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

		sf, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer sf.Close()

		var sv mitre.Vulnerability
		if err := json.NewDecoder(sf).Decode(&sv); err != nil {
			return errors.Wrap(err, "decode json")
		}

		y := strings.Split(sv.CVE, "-")[1]
		if err := os.MkdirAll(filepath.Join(options.destDir, y), os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", filepath.Join(options.destDir, y))
		}

		df, err := os.OpenFile(filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", sv.CVE)), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return errors.Wrapf(err, "open %s", filepath.Join(options.destDir, y, fmt.Sprintf("%s.json", sv.CVE)))
		}
		defer df.Close()

		var dv build.Vulnerability
		if err := json.NewDecoder(df).Decode(&dv); err != nil && !errors.Is(err, io.EOF) {
			return errors.Wrap(err, "decode json")
		}

		fill(&sv, &dv)

		enc := json.NewEncoder(df)
		enc.SetIndent("", "  ")
		if err := enc.Encode(dv); err != nil {
			return errors.Wrap(err, "encode json")
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk mitre")
	}

	return nil
}

func fill(sv *mitre.Vulnerability, dv *build.Vulnerability) {
	if dv.ID == "" {
		dv.ID = sv.CVE
	}

	if sv.Title != "" {
		if dv.Title == nil {
			dv.Title = map[string]string{}
		}
		dv.Title["mitre"] = sv.Title
	}

	if sv.Notes.Description != "" {
		if dv.Description == nil {
			dv.Description = map[string]string{}
		}
		dv.Description["mitre"] = sv.Notes.Description
	}
	if sv.Notes.Published != nil {
		if dv.Published == nil {
			dv.Published = map[string]time.Time{}
		}
		dv.Published["mitre"] = *sv.Notes.Published
	}
	if sv.Notes.Modified != nil {
		if dv.Modified == nil {
			dv.Modified = map[string]time.Time{}
		}
		dv.Modified["mitre"] = *sv.Notes.Modified
	}
	for _, r := range sv.References {
		dv.References = append(dv.References, build.Reference{
			Source: strings.Split(r.Description, ":")[0],
			ID:     r.Description,
			URL:    r.URL,
		})
	}
}
