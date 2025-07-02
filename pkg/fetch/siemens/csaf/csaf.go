package csaf

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
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

type concurrencyOption int

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		dataURL:     dataURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "siemens", "csaf"),
		retry:       3,
		concurrency: 1,
		wait:        3,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Siemens Security Advisories (CSAF)")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	us, err := options.fetchFeed(client)
	if err != nil {
		return errors.Wrap(err, "fetch feed")
	}
	if err := options.fetchCSAF(client, us); err != nil {
		return errors.Wrap(err, "fetch csaf")
	}
	return nil
}

func (opts options) fetchFeed(client *utilhttp.Client) ([]string, error) {
	resp, err := client.Get(opts.dataURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch feed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var feed feed
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	var urls []string
	for _, entry := range feed.Feed.Entry {
		urls = append(urls, entry.Content.Src)
	}

	return urls, nil
}

func (opts options) fetchCSAF(client *utilhttp.Client, urls []string) error {
	if err := client.PipelineGet(urls, opts.concurrency, opts.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var csaf CSAF
		if err := json.NewDecoder(resp.Body).Decode(&csaf); err != nil {
			return errors.Wrap(err, "decode json")
		}

		t, err := time.Parse("2006-01-02T15:04:05Z", csaf.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "unexpected published format. expected: %q, actual: %q", "2006-01-02T15:04:05Z", csaf.Document.Tracking.InitialReleaseDate)
		}

		if err := util.Write(filepath.Join(opts.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)), csaf); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
