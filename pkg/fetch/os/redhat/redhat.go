package redhat

import (
	"log"
	"path/filepath"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/redhat/oval"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	"github.com/pkg/errors"
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
		dir:   filepath.Join(util.SourceDir(), "redhat"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch RedHat OVAL")
	if err := oval.Fetch(oval.WithDir(filepath.Join(options.dir, "oval")), oval.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch redhat oval")
	}

	// log.Println("[INFO] Fetch RedHat API")
	// if err := api.Fetch(api.WithDir(filepath.Join(options.dir, "api")), api.WithRetry(options.retry)); err != nil {
	// 	return errors.Wrap(err, "fetch redhat api")
	// }

	return nil
}
