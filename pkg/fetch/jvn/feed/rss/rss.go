package rss

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://jvndb.jvn.jp/ja/feed/checksum.txt"

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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
		dir:     filepath.Join(util.CacheDir(), "jvn", "feed", "rss"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch JVNDB RSS")
	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "get checksum")
	}

	var cs []checksum
	if err := json.Unmarshal(bs, &cs); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	var filtered []checksum
	for _, c := range cs {
		if strings.HasPrefix(c.Filename, "jvndb") && !strings.Contains(c.Filename, "_detail_") {
			filtered = append(filtered, c)
		}
	}

	slices.SortFunc(filtered, func(a, b checksum) int {
		at, aerr := time.Parse("2006/01/02 15:04:05", a.LastModified)
		bt, berr := time.Parse("2006/01/02 15:04:05", b.LastModified)
		if aerr != nil && berr != nil {
			return 0
		}
		if aerr != nil || at.Before(bt) {
			return +1
		}
		if berr != nil || at.After(bt) {
			return -1
		}
		return 0
	})

	advisories := map[string]Item{}
	for _, c := range filtered {
		log.Printf("[INFO] Fetch JVNDB RSS Feed %s", c.Filename)
		bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(c.URL)
		if err != nil {
			return errors.Wrap(err, "fetch jvndb rss")
		}

		var root root
		if err := xml.Unmarshal(bs, &root); err != nil {
			return errors.Wrap(err, "unmarshal xml")
		}

		for _, i := range root.Item {
			if ii, ok := advisories[i.Identifier]; ok {
				a, _ := time.Parse("2006-01-02T15:04-07:00", ii.Modified)
				b, _ := time.Parse("2006-01-02T15:04-07:00", i.Modified)
				if a.After(b) {
					continue
				}
			}
			advisories[i.Identifier] = i
		}
	}

	bar := pb.StartNew(len(advisories))
	for _, a := range advisories {
		y := strings.Split(a.Identifier, "-")[1]
		if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", a.Identifier)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", a.Identifier)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
