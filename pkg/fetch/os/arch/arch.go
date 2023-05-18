package arch

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const advisoryURL = "https://security.archlinux.org/json"

type options struct {
	advisoryURL string
	dir         string
	retry       int
}

type Option interface {
	apply(*options)
}

type advisoryURLOption string

func (a advisoryURLOption) apply(opts *options) {
	opts.advisoryURL = string(a)
}

func WithAdvisoryURL(advisoryURL string) Option {
	return advisoryURLOption(advisoryURL)
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
		advisoryURL: advisoryURL,
		dir:         filepath.Join(util.SourceDir(), "arch"),
		retry:       3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Arch Linux")
	bs, err := util.FetchURL(options.advisoryURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}

	var vs vulnerabilityGroups
	if err := json.Unmarshal(bs, &vs); err != nil {
		return errors.Wrap(err, "unmarshal advisory")
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}
	if err := os.MkdirAll(options.dir, os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", options.dir)
	}

	bar := pb.StartNew(len(vs))
	for _, v := range vs {
		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json.gz", v.Name)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json.gz", v.Name)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
