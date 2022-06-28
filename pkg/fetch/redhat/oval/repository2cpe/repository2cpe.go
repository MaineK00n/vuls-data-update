package repository2cpe

import (
	"encoding/json"
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	repositoryToCPEURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"
)

type options struct {
	repositoryToCPEURL string
	dir                string
	retry              int
}

type Option interface {
	apply(*options)
}

type repositoryToCPEURLOption string

func (u repositoryToCPEURLOption) apply(opts *options) {
	opts.repositoryToCPEURL = string(u)
}

func WithRepositoryToCPEURL(u string) Option {
	return repositoryToCPEURLOption(u)
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
		repositoryToCPEURL: repositoryToCPEURL,
		dir:                filepath.Join(util.CacheDir(), "redhat", "oval", "repository-to-cpe"),
		retry:              3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Redhat Repository to CPE")
	bs, err := utilhttp.Get(options.repositoryToCPEURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch repository to cpe")
	}

	var repo2cpe RepositoryToCPE
	if err := json.Unmarshal(bs, &repo2cpe); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	if err := util.Write(filepath.Join(options.dir, "repository-to-cpe.json"), repo2cpe); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "repository-to-cpe.json"))
	}

	return nil
}
