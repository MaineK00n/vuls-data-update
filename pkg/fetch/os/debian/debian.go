package debian

import (
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian/oval"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian/tracker"
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
		dir:   filepath.Join(util.CacheDir(), "source", "debian"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Debian OVAL")
	if err := oval.Fetch(oval.WithDir(filepath.Join(options.dir, "oval")), oval.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch debian oval")
	}

	log.Println("[INFO] Fetch Debian Security Tracker")
	if err := tracker.Fetch(tracker.WithDir(filepath.Join(options.dir, "tracker")), tracker.WithRetry(options.retry)); err != nil {
		return errors.Wrap(err, "fetch debian security tracker")
	}

	return nil
}
