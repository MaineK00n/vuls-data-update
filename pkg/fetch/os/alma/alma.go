package alma

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
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
		dir:   filepath.Join(util.SourceDir(), "alma"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	for v, url := range options.urls {
		log.Printf("[INFO] Fetch AlmaLinux %s", v)
		bs, err := util.FetchURL(url, options.retry)
		if err != nil {
			return errors.Wrapf(err, "fetch almalinux %s errata", v)
		}

		var root Root
		if err := json.Unmarshal(bs, &root); err != nil {
			return errors.Wrapf(err, "unmarshal almalinux %s", v)
		}

		var secErrata []Erratum
		for _, e := range root.Data {
			if e.Type != "security" {
				continue
			}
			secErrata = append(secErrata, e)
		}

		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		bar := pb.StartNew(len(secErrata))
		for _, e := range secErrata {
			if err := func() error {
				y := strings.Split(strings.TrimPrefix(e.ID, "ALSA-"), ":")[0]

				if err := os.MkdirAll(filepath.Join(dir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", dir)
				}

				f, err := os.Create(filepath.Join(dir, y, fmt.Sprintf("%s.json", e.ID)))
				if err != nil {
					return errors.Wrapf(err, "create %s", filepath.Join(dir, y, fmt.Sprintf("%s.json", e.ID)))
				}
				defer f.Close()

				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(e); err != nil {
					return errors.Wrap(err, "encode data")
				}
				return nil
			}(); err != nil {
				return err
			}

			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}
