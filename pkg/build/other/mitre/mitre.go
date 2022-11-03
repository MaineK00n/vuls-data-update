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

		fillVulnerability(&dv, &sv)

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
