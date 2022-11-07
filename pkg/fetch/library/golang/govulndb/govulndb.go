package govulndb

import (
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://storage.googleapis.com/go-vulndb"

type options struct {
	dataURL        string
	dir            string
	retry          int
	compressFormat string
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
		dir:            filepath.Join(util.SourceDir(), "golang", "go-vulndb"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Golang go-vulndb")
	_, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch go-vulndb data")
	}

	return nil
}
