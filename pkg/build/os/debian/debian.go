package debian

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build/os/debian/oval"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/debian/tracker"
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
		srcDir:        filepath.Join(util.SourceDir(), "debian"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "debian"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := oval.Build(oval.WithSrcDir(filepath.Join(options.srcDir, "oval")), oval.WithDestVulnDir(options.destVulnDir), oval.WithDestDetectDir(filepath.Join(options.destDetectDir, "oval"))); err != nil {
		return errors.Wrap(err, "build debian oval")
	}

	if err := tracker.Build(tracker.WithSrcDir(filepath.Join(options.srcDir, "tracker")), tracker.WithDestVulnDir(options.destVulnDir), tracker.WithDestDetectDir(filepath.Join(options.destDetectDir, "tracker"))); err != nil {
		return errors.Wrap(err, "build debian security tracker")
	}

	return nil
}