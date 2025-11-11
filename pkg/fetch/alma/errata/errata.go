package errata

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const urlFormat = "https://errata.almalinux.org/%s/errata.full.json"

var versions = []string{"8", "9", "10"}

type options struct {
	urls  map[string]string
	dir   string
	retry int
}

type Option interface {
	apply(*options)
}

type urlOption map[string]string

func (u urlOption) apply(opts *options) {
	opts.urls = u
}

func WithURLs(urls map[string]string) Option {
	return urlOption(urls)
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
	urls := make(map[string]string)
	for _, v := range versions {
		urls[v] = fmt.Sprintf(urlFormat, v)
	}

	options := &options{
		urls:  urls,
		dir:   filepath.Join(util.CacheDir(), "fetch", "alma", "errata"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	for v, url := range options.urls {
		log.Printf("[INFO] Fetch AlmaLinux %s", v)
		advs, err := func() ([]Erratum, error) {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(url)
			if err != nil {
				return nil, errors.Wrapf(err, "fetch almalinux %s errata", v)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var root root
			if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
				return nil, errors.Wrapf(err, "decode almalinux %s", v)
			}

			return root.Data, nil
		}()
		if err != nil {
			return errors.Wrapf(err, "fetch almalinux %s", v)
		}

		bar := progressbar.Default(int64(len(advs)))
		for _, a := range advs {
			splitted, err := util.Split(a.ID, "-", ":")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALSA-yyyy:\\d{4}", a.ID)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALSA-yyyy:\\d{4}", a.ID)
			}

			if err := util.Write(filepath.Join(options.dir, v, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, splitted[0], splitted[1], fmt.Sprintf("%s.json", a.ID)))
			}

			_ = bar.Add(1)
		}
		_ = bar.Close()
	}
	return nil
}
