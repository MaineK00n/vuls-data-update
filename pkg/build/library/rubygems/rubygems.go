package rubygems

import (
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build/library/rubygems/db"
	"github.com/MaineK00n/vuls-data-update/pkg/build/library/rubygems/ghsa"
	"github.com/MaineK00n/vuls-data-update/pkg/build/library/rubygems/glsa"
	"github.com/MaineK00n/vuls-data-update/pkg/build/library/rubygems/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
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
		srcDir:        filepath.Join(util.SourceDir(), "rubygems"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "library", "rubygems"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build Rubygems DB")
	if err := db.Build(db.WithSrcDir(filepath.Join(options.srcDir, "db")), db.WithDestVulnDir(options.destVulnDir), db.WithDestDetectDir(filepath.Join(options.destDetectDir, "db"))); err != nil {
		return errors.Wrap(err, "build rubygems db")
	}

	log.Println("[INFO] Build Rubygems GHSA")
	if err := ghsa.Build(ghsa.WithSrcDir(filepath.Join(options.srcDir, "ghsa")), ghsa.WithDestVulnDir(options.destVulnDir), ghsa.WithDestDetectDir(filepath.Join(options.destDetectDir, "ghsa"))); err != nil {
		return errors.Wrap(err, "build rubygems ghsa")
	}

	log.Println("[INFO] Build Rubygems GLSA")
	if err := glsa.Build(glsa.WithSrcDir(filepath.Join(options.srcDir, "glsa")), glsa.WithDestVulnDir(options.destVulnDir), glsa.WithDestDetectDir(filepath.Join(options.destDetectDir, "glsa"))); err != nil {
		return errors.Wrap(err, "build rubygems glsa")
	}

	log.Println("[INFO] Build Rubygems OSV")
	if err := osv.Build(osv.WithSrcDir(filepath.Join(options.srcDir, "osv")), osv.WithDestVulnDir(options.destVulnDir), osv.WithDestDetectDir(filepath.Join(options.destDetectDir, "osv"))); err != nil {
		return errors.Wrap(err, "build rubygems osv")
	}

	return nil
}
