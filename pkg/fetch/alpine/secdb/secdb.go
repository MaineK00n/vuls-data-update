package secdb

import (
	"bytes"
	"encoding/json"
	"log"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://secdb.alpinelinux.org/"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithBaseURL(url string) Option {
	return baseURLOption(url)
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
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "alpine"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	releases, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, r := range releases {
		log.Printf("[INFO] Fetch Alpine Linux %s", r)
		files, err := options.walkDistroVersion(r)
		if err != nil {
			return errors.Wrapf(err, "walk alpine linux %s", r)
		}

		advs, err := options.fetchAdvisory(r, files)
		if err != nil {
			return errors.Wrapf(err, "fetch alpine linux %s advisory %q", r, files)
		}

		for filename, adv := range advs {
			if err := util.Write(filepath.Join(options.dir, strings.TrimPrefix(r, "v"), filename), adv); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, strings.TrimPrefix(r, "v"), filename))
			}
		}
	}
	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var releases []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "v") {
			return
		}
		releases = append(releases, strings.TrimSuffix(txt, "/"))
	})
	return releases, nil
}

func (opts options) walkDistroVersion(release string) ([]string, error) {
	u, err := url.JoinPath(opts.baseURL, release)
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch alpine linux %s index of", release)
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var files []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasSuffix(txt, ".json") {
			return
		}
		files = append(files, txt)
	})
	return files, nil
}

func (opts options) fetchAdvisory(release string, files []string) (map[string]Advisory, error) {
	advs := make(map[string]Advisory, 2)
	for _, f := range files {
		u, err := url.JoinPath(opts.baseURL, release, f)
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}

		bs, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
		if err != nil {
			return nil, errors.Wrapf(err, "fetch alpine linux %s %s", release, f)
		}

		var a Advisory
		if err := json.Unmarshal(bs, &a); err != nil {
			return nil, errors.Wrapf(err, "unmarshal alpine linux %s %s", release, f)
		}
		advs[f] = a
	}
	return advs, nil
}
