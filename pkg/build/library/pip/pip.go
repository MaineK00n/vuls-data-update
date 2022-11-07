package pip

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build/library/pip/db"
	"github.com/MaineK00n/vuls-data-update/pkg/build/library/pip/ghsa"
	"github.com/MaineK00n/vuls-data-update/pkg/build/library/pip/glsa"
	"github.com/MaineK00n/vuls-data-update/pkg/build/library/pip/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/build/util"
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
		srcDir:             filepath.Join(util.SourceDir(), "pip"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "library", "pip"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := db.Build(db.WithSrcDir(filepath.Join(options.srcDir, "db")), db.WithSrcCompressFormat(options.srcCompressFormat), db.WithDestVulnDir(options.destVulnDir), db.WithDestDetectDir(filepath.Join(options.destDetectDir, "db")), db.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build pip db")
	}

	if err := ghsa.Build(ghsa.WithSrcDir(filepath.Join(options.srcDir, "ghsa")), ghsa.WithSrcCompressFormat(options.srcCompressFormat), ghsa.WithDestVulnDir(options.destVulnDir), ghsa.WithDestDetectDir(filepath.Join(options.destDetectDir, "ghsa")), ghsa.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build pip ghsa")
	}

	if err := glsa.Build(glsa.WithSrcDir(filepath.Join(options.srcDir, "glsa")), glsa.WithSrcCompressFormat(options.srcCompressFormat), glsa.WithDestVulnDir(options.destVulnDir), glsa.WithDestDetectDir(filepath.Join(options.destDetectDir, "glsa")), glsa.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build pip glsa")
	}

	if err := osv.Build(osv.WithSrcDir(filepath.Join(options.srcDir, "osv")), osv.WithSrcCompressFormat(options.srcCompressFormat), osv.WithDestVulnDir(options.destVulnDir), osv.WithDestDetectDir(filepath.Join(options.destDetectDir, "osv")), osv.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build pip osv")
	}

	return nil
}
