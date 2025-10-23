package csaf

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://fortiguard.fortinet.com/psirt/%s"

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption int

func (w waitOption) apply(opts *options) {
	opts.wait = int(w)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(args []string, opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "fortinet", "csaf"),
		retry:       3,
		concurrency: 3,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	us, err := options.fetchCSAFURLs(args)
	if err != nil {
		return errors.Wrap(err, "fetch CSAF URLs")
	}

	if err := options.fetchCSAF(us); err != nil {
		return errors.Wrap(err, "fetch CSAF")
	}

	return nil
}

func (opts options) fetchCSAFURLs(ids []string) ([]string, error) {
	log.Printf("[INFO] Fetch Fortinet CSAF URLs")

	urls := make([]string, 0, len(ids))
	for _, arg := range ids {
		urls = append(urls, fmt.Sprintf(opts.baseURL, arg))
	}

	csafURLs := make([]string, 0, len(ids))
	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).PipelineGet(urls, opts.concurrency, opts.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create new document from reader")
		}

		var u string
		for _, tr := range doc.Find("div.sidebar table tr").EachIter() {
			td := tr.Find("td")
			if td.Length() != 2 {
				return errors.Errorf("unexpected table data cell length. expected: %d, actual: %d", 2, td.Length())
			}
			switch td.Eq(0).Text() {
			case "Download":
				for _, a := range td.Find("p > a").EachIter() {
					href, ok := a.Attr("href")
					if !ok {
						return errors.New("href attribute not found in anchor tag")
					}

					switch {
					case strings.HasPrefix(href, "/psirt/cvrf/"):
						continue
					case strings.HasPrefix(href, "/psirt/csaf/"):
						_, rhs, ok := strings.Cut(href, "?csaf_url=")
						if !ok {
							return errors.Errorf("unexpected CSAF href format. expected: %q, actual: %q", "/psirt/csaf/<Advisory ID>?csaf_url=<CSAF URL>", href)
						}
						u = rhs
					default:
						return errors.Errorf("unexpected download href format. expected: %q, actual: %q", []string{"/psirt/cvrf/<Advisory ID>", "/psirt/csaf/<Advisory ID>?csaf_url=<CSAF URL>"}, href)
					}
				}
			default:
				continue
			}
		}
		if u == "" {
			return errors.New("CSAF download URL not found")
		}
		csafURLs = append(csafURLs, u)

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline get")
	}

	return csafURLs, nil
}

func (opts options) fetchCSAF(urls []string) error {
	log.Printf("[INFO] Fetch Fortinet CSAF")

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).PipelineGet(urls, opts.concurrency, opts.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var a CSAF
		if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
			return errors.Wrap(err, "decode json")
		}

		t, err := time.Parse("2006-01-02T15:04:05", a.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "failed to parse InitialReleaseDate option. expected: %q, actual: %q", "2006-01-02T15:04:05", a.Document.Tracking.InitialReleaseDate)
		}

		if err := util.Write(filepath.Join(opts.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", a.Document.Tracking.ID)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", a.Document.Tracking.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
