package arch

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
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
		dir:         filepath.Join(util.CacheDir(), "fetch", "arch"),
		retry:       3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Arch Linux")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.advisoryURL)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var vs vulnerabilityGroups
	if err := json.NewDecoder(resp.Body).Decode(&vs); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar := progressbar.Default(int64(len(vs)))
	for _, v := range vs {
		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json", v.Name)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json", v.Name)))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
