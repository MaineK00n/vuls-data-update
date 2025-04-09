package secdb

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
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
		dir:     filepath.Join(util.CacheDir(), "fetch", "alpine", "secdb"),
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

		for _, f := range files {
			u, err := url.JoinPath(options.baseURL, r, f)
			if err != nil {
				return errors.Wrap(err, "join url path")
			}

			a, err := func() (*Advisory, error) {
				resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
				if err != nil {
					return nil, errors.Wrapf(err, "fetch alpine linux %s %s", r, f)
				}
				defer resp.Body.Close() //nolint:errcheck

				if resp.StatusCode != http.StatusOK {
					_, _ = io.Copy(io.Discard, resp.Body)
					return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
				}

				var a Advisory
				if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
					return nil, errors.Wrap(err, "decode json")
				}

				return &a, nil
			}()
			if err != nil {
				return errors.Wrapf(err, "fetch alpine linux %s %s", r, f)
			}

			if err := util.Write(filepath.Join(options.dir, strings.TrimPrefix(r, "v"), f), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, strings.TrimPrefix(r, "v"), f))
			}
		}
	}
	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var releases []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "v") && !strings.HasPrefix(txt, "edge") {
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

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch alpine linux %s index of", release)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
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
