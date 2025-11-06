package csaf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://security.nozominetworks.com/csaf/"

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
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

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "nozominetworks", "csaf"),
		retry:       3,
		concurrency: 3,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Nozomi Networks CSAF")
	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (o options) fetch() error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(o.retry))

	u, err := url.JoinPath(o.baseURL, "index.txt")
	if err != nil {
		return errors.Wrap(err, "url join")
	}

	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var us []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		u, err := url.JoinPath(o.baseURL, scanner.Text())
		if err != nil {
			return errors.Wrap(err, "url join")
		}
		us = append(us, u)
	}
	if err := scanner.Err(); err != nil {
		return errors.Wrap(err, "scanner encounter error")
	}

	if err := client.PipelineGet(us, o.concurrency, o.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var csaf CSAF
		if err := json.NewDecoder(resp.Body).Decode(&csaf); err != nil {
			return errors.Wrap(err, "decode json")
		}

		t, err := time.Parse(time.RFC3339, csaf.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "failed to parse InitialReleaseDate option. expected: %q, actual: %q", time.RFC3339, csaf.Document.Tracking.InitialReleaseDate)
		}

		if err := util.Write(filepath.Join(o.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)), csaf); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
