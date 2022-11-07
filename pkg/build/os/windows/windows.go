package windows

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build/os/windows/bulletin"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/windows/cvrf"
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
		srcDir:             filepath.Join(util.SourceDir(), "windows"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "windows"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := bulletin.Build(bulletin.WithSrcDir(filepath.Join(options.srcDir, "bulletin")), bulletin.WithSrcCompressFormat(options.srcCompressFormat), bulletin.WithDestVulnDir(options.destVulnDir), bulletin.WithDestDetectDir(filepath.Join(options.destDetectDir, "bulletin")), bulletin.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build windows bulletin")
	}

	if err := cvrf.Build(cvrf.WithSrcDir(filepath.Join(options.srcDir, "cvrf")), cvrf.WithSrcCompressFormat(options.srcCompressFormat), cvrf.WithDestVulnDir(options.destVulnDir), cvrf.WithDestDetectDir(filepath.Join(options.destDetectDir, "cvrf")), cvrf.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build windows cvrf")
	}

	return nil
}
