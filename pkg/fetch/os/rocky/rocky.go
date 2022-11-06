package rocky

import (
	"encoding/json"
	"path/filepath"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	"github.com/pkg/errors"
)

// modular package: https://kojidev.rockylinux.org/kojifiles/packages/httpd/2.4/8030020210413025317.30b713e6/

const dataURL = "https://errata.rockylinux.org/api/advisories"

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
		dir:     filepath.Join(util.SourceDir(), "rocky"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch cvrf data")
	}

	var advisories interface{}
	if err := json.Unmarshal(bs, &advisories); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	return nil
}
