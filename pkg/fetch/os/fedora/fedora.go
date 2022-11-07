package fedora

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://dl.fedoraproject.org/pub/fedora/linux/"

// https://dl.fedoraproject.org/pub/fedora-secondary/
// https://dl.fedoraproject.org/pub/archive/fedora/linux/
// https://dl.fedoraproject.org/pub/archive/fedora-secondary/
// get path to updateinfo and modules from fullfilelist (e.g. https://dl.fedoraproject.org/pub/fedora/fullfilelist)

type options struct {
	dataURL        string
	dir            string
	retry          int
	compressFormat string
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		dataURL:        dataURL,
		dir:            filepath.Join(util.SourceDir(), "fedora"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	_, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch updateinfo data")
	}

	return nil
}
