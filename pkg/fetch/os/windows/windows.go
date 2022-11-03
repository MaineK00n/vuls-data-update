package windows

import (
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/windows/bulletin"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/windows/cvrf"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type options struct {
	dir   string
	retry int
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

func Fetch(opts ...Option) error {
	options := &options{
		dir:   filepath.Join(util.SourceDir(), "windows"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Windows Bulletin")
	if err := bulletin.Fetch(bulletin.WithDir(filepath.Join(options.dir, "bulletin")), bulletin.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch windows bulletin")
	}

	log.Println("[INFO] Fetch Windows CVRF")
	if err := cvrf.Fetch(cvrf.WithDir(filepath.Join(options.dir, "cvrf")), cvrf.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch windows cvrf")
	}

	return nil
}
