package windows

import (
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/build/os/windows/bulletin"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/windows/cvrf"
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
		srcDir:        filepath.Join(util.SourceDir(), "windows"),
		destVulnDir:   filepath.Join(util.DestDir(), "vulnerability"),
		destDetectDir: filepath.Join(util.DestDir(), "os", "windows"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Build Windows Bulletin")
	if err := bulletin.Build(bulletin.WithSrcDir(filepath.Join(options.srcDir, "bulletin")), bulletin.WithDestVulnDir(options.destVulnDir), bulletin.WithDestDetectDir(filepath.Join(options.destDetectDir, "bulletin"))); err != nil {
		return errors.Wrap(err, "build windows bulletin")
	}

	log.Println("[INFO] Build Windows CVRF")
	if err := cvrf.Build(cvrf.WithSrcDir(filepath.Join(options.srcDir, "cvrf")), cvrf.WithDestVulnDir(options.destVulnDir), cvrf.WithDestDetectDir(filepath.Join(options.destDetectDir, "cvrf"))); err != nil {
		return errors.Wrap(err, "build windows cvrf")
	}

	return nil
}
