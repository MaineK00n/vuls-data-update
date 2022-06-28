package epel

import (
	"path/filepath"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	"github.com/pkg/errors"
)

const dataURL = "https://dl.fedoraproject.org/pub/epel/"

// https://dl.fedoraproject.org/pub/archive/epel/
// get path to updateinfo and modules from fullfilelist (e.g. https://dl.fedoraproject.org/pub/fedora/fullfilelist)

type options struct {
	dataURL string
	dir     string
	retry   int
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

func Fetch(opts ...Option) error {
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.SourceDir(), "epel"),
		retry:   3,
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
