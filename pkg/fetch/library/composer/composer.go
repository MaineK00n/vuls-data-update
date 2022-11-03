package composer

import (
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/composer/db"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/composer/ghsa"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/composer/glsa"
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
		dir:   filepath.Join(util.SourceDir(), "composer"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Composer DB")
	if err := db.Fetch(db.WithDir(filepath.Join(options.dir, "db")), db.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch composer db")
	}

	log.Println("[INFO] Fetch Composer GHSA")
	if err := ghsa.Fetch(ghsa.WithDir(filepath.Join(options.dir, "ghsa")), ghsa.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch composer ghsa")
	}

	log.Println("[INFO] Fetch Composer GLSA")
	if err := glsa.Fetch(glsa.WithDir(filepath.Join(options.dir, "glsa")), glsa.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch composer glsa")
	}

	return nil
}
