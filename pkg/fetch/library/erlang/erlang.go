package erlang

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://developer.github.com/v4/enum/securityadvisoryecosystem/" // Erlang

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type repoURLOption string

func (u repoURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithRepoURL(repoURL string) Option {
	return repoURLOption(repoURL)
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
		dir:     filepath.Join(util.SourceDir(), "erlang"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	_, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch ghsa data")
	}

	return nil
}
