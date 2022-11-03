package db

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const defaultRepoURL = "https://github.com/pypa/advisory-database"

type options struct {
	repoURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type repoURLOption string

func (u repoURLOption) apply(opts *options) {
	opts.repoURL = string(u)
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
		repoURL: defaultRepoURL,
		dir:     filepath.Join(util.SourceDir(), "pip", "db"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	cloneDir := filepath.Join(util.SourceDir(), "clone")
	if err := os.RemoveAll(cloneDir); err != nil {
		return errors.Wrapf(err, "remove %s", cloneDir)
	}
	if err := os.MkdirAll(cloneDir, os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", cloneDir)
	}

	if err := exec.Command("git", "clone", "--depth", "1", options.repoURL, cloneDir).Run(); err != nil {
		return errors.Wrapf(err, "git clone --depth 1 %s %s", options.repoURL, cloneDir)
	}

	return nil
}
