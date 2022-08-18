package alma

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

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

		var advs []Advisory
		calcDateFn := func(v int) *time.Time {
			t := time.Unix(int64(v), 0).UTC()
			return &t
		}
		for _, e := range root.Data {
			if e.Type != "security" {
				continue
			}
			advs = append(advs, Advisory{
				ID:          e.ID,
				Type:        e.Type,
				Title:       e.Title,
				Description: e.Description,
				Severity:    e.Severity,
				Packages:    e.Packages,
				Modules:     e.Modules,
				References:  e.References,
				IssuedDate:  calcDateFn(e.IssuedDate),
				UpdatedDate: calcDateFn(e.UpdatedDate),
			})
		}

		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		bar := pb.StartNew(len(advs))
		for _, a := range advs {
			if err := func() error {
				y := strings.Split(strings.TrimPrefix(a.ID, "ALSA-"), ":")[0]

				if err := os.MkdirAll(filepath.Join(dir, y), os.ModePerm); err != nil {
					return errors.Wrapf(err, "mkdir %s", dir)
				}

				f, err := os.Create(filepath.Join(dir, y, fmt.Sprintf("%s.json", a.ID)))
				if err != nil {
					return errors.Wrapf(err, "create %s", filepath.Join(dir, y, fmt.Sprintf("%s.json", a.ID)))
				}
				defer f.Close()

				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(a); err != nil {
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
