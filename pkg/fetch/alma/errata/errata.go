package errata

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const urlFormat = "https://errata.almalinux.org/%s/errata.full.json"

var versions = []string{"8", "9"}

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
	urls := map[string]string{}
	for _, v := range versions {
		urls[v] = fmt.Sprintf(urlFormat, v)
	}

	options := &options{
		urls:  urls,
		dir:   filepath.Join(util.CacheDir(), "alma", "errata"),
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
		bs, err := utilhttp.Get(url, options.retry)
		if err != nil {
			return errors.Wrapf(err, "fetch almalinux %s errata", v)
		}

		var root root
		if err := json.Unmarshal(bs, &root); err != nil {
			return errors.Wrapf(err, "unmarshal almalinux %s", v)
		}

		var advs []Erratum
		for _, d := range root.Data {
			if d.Type != "security" {
				continue
			}
			advs = append(advs, d)
		}

		bar := pb.StartNew(len(advs))
		for _, a := range advs {
			y := strings.Split(strings.TrimPrefix(a.ID, "ALSA-"), ":")[0]
			if _, err := strconv.Atoi(y); err != nil {
				continue
			}

			if err := util.Write(filepath.Join(options.dir, v, y, fmt.Sprintf("%s.json", a.ID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, y, fmt.Sprintf("%s.json", a.ID)))
			}

			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}
