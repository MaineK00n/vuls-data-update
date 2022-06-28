package jvn

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	urlFormat  = "https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_%d.rdf"
	oldestYear = 1998
)

type options struct {
	urls  []string
	dir   string
	retry int
}

type Option interface {
	apply(*options)
}

type urlOption []string

func (u urlOption) apply(opts *options) {
	opts.urls = u
}

func WithURLs(urls []string) Option {
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
	var urls []string
	for y := oldestYear; y <= time.Now().Year(); y++ {
		urls = append(urls, fmt.Sprintf(urlFormat, y))
	}

	options := &options{
		urls:  urls,
		dir:   filepath.Join(util.CacheDir(), "jvn"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	for _, u := range options.urls {
		uu, err := url.Parse(u)
		if err != nil {
			return errors.Wrap(err, "parse url")
		}
		y := strings.TrimSuffix(strings.TrimPrefix(path.Base(uu.Path), "jvndb_detail_"), ".rdf")
		if _, err := strconv.Atoi(y); err != nil {
			continue
		}

		log.Printf("[INFO] Fetch JVNDB Feed %s", y)
		bs, err := utilhttp.Get(u, options.retry)
		if err != nil {
			return errors.Wrapf(err, "fetch jvndb %s feed", y)
		}

		var feed feed
		if err := xml.Unmarshal(bs, &feed); err != nil {
			return errors.Wrap(err, "unmarshal xml")
		}

		for _, v := range feed.Vulinfo {
			for i, item := range v.Affected {
				var vs []string
				for _, v := range item.VersionNumber {
					if v == "" {
						continue
					}
					vs = append(vs, v)
				}
				v.Affected[i].VersionNumber = vs
			}
		}

		bar := pb.StartNew(len(feed.Vulinfo))
		for _, a := range feed.Vulinfo {
			if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", a.VulinfoID)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", a.VulinfoID)))
			}

			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}
