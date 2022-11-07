package debian

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build/os/debian/oval"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/debian/tracker"
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
		srcDir:             filepath.Join(util.SourceDir(), "debian"),
		srcCompressFormat:  "",
		destVulnDir:        filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir:      filepath.Join(util.DestDir(), "os", "debian"),
		destCompressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := oval.Build(oval.WithSrcDir(filepath.Join(options.srcDir, "oval")), oval.WithSrcCompressFormat(options.srcCompressFormat), oval.WithDestVulnDir(options.destVulnDir), oval.WithDestDetectDir(filepath.Join(options.destDetectDir, "oval")), oval.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build debian oval")
	}

	if err := tracker.Build(tracker.WithSrcDir(filepath.Join(options.srcDir, "tracker")), tracker.WithSrcCompressFormat(options.srcCompressFormat), tracker.WithDestVulnDir(options.destVulnDir), tracker.WithDestDetectDir(filepath.Join(options.destDetectDir, "tracker")), tracker.WithDestCompressFormat(options.destCompressFormat)); err != nil {
		return errors.Wrap(err, "build debian security tracker")
	}

	return nil
}
