package cwe

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
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
		srcDir:  filepath.Join(util.SourceDir(), "cwe"),
		destDir: filepath.Join(util.DestDir(), "vulnerability"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Build Common Weakness Enumeration: CWE")
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

		return nil
	}); err != nil {
		return errors.Wrap(err, "walk cwe")
	}

	return nil
}
