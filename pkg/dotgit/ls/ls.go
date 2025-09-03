package ls

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	dir string
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

func List(opts ...Option) ([]string, error) {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "dotgit"),
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	ds, err := filepath.Glob(filepath.Join(options.dir, "vuls-data-*"))
	if err != nil {
		return nil, errors.Wrap(err, "list dotgits")
	}

	return ds, nil
}
