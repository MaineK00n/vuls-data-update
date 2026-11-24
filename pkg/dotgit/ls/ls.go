package ls

import (
	"cmp"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

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

	// The directory is a path, not a pattern. Globbing dir/vuls-data-* would
	// list whatever a dir holding [ or * matched instead. os.ReadDir takes an
	// empty dir for a missing one, where filepath.Join takes it for the
	// current directory.
	dir := cmp.Or(options.dir, ".")
	es, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, errors.Wrapf(err, "read dir %s", dir)
	}

	ds := make([]string, 0, len(es))
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "vuls-data-") {
			ds = append(ds, filepath.Join(dir, e.Name()))
		}
	}

	return ds, nil
}
