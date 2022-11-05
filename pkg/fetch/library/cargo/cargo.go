package cargo

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/cargo/db"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/cargo/ghsa"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/cargo/osv"
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
		dir:   filepath.Join(util.SourceDir(), "cargo"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := db.Fetch(db.WithDir(filepath.Join(options.dir, "db")), db.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch cargo db")
	}

	if err := ghsa.Fetch(ghsa.WithDir(filepath.Join(options.dir, "ghsa")), ghsa.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch cargo ghsa")
	}

	if err := osv.Fetch(osv.WithDir(filepath.Join(options.dir, "osv")), osv.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch cargo osv")
	}

	return nil
}
