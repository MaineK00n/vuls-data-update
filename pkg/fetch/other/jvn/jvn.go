package jvn

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const (
	urlFormat  = "https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_%d.rdf"
	oldestYear = 1998
)

type options struct {
	urls           []string
	dir            string
	retry          int
	compressFormat string
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	var urls []string
	for y := oldestYear; y <= time.Now().Year(); y++ {
		urls = append(urls, fmt.Sprintf(urlFormat, y))
	}

	options := &options{
		urls:  urls,
		dir:   filepath.Join(util.SourceDir(), "jvn"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
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
		bs, err := util.FetchURL(u, options.retry)
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

			for i, item := range v.History {
				t := item.DateTime.UTC()
				v.History[i].DateTime = &t
			}

			t := v.DateFirstPublished.UTC()
			v.DateFirstPublished = &t
			t = v.DateLastUpdated.UTC()
			v.DateLastUpdated = &t
			t = v.DatePublic.UTC()
			v.DatePublic = &t
		}

		dir := filepath.Join(options.dir, y)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", dir)
		}
		bar := pb.StartNew(len(feed.Vulinfo))
		for _, a := range feed.Vulinfo {
			bs, err := json.Marshal(a)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(dir, fmt.Sprintf("%s.json", a.VulinfoID)), options.compressFormat), bs, options.compressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(dir, a.VulinfoID))
			}

			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}
