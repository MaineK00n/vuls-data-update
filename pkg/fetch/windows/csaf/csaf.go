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

const baseURL = "https://msrc.microsoft.com/csaf/advisories/"

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
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "windows", "csaf"),
		retry:       3,
		concurrency: 5,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Windows CSAF")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	ls, err := options.fetchIndex(client)
	if err != nil {
		return errors.Wrap(err, "fetch index")
	}

	us := make([]string, 0, len(ls))
	for _, l := range ls {
		u, err := url.JoinPath(options.baseURL, l)
		if err != nil {
			return errors.Wrap(err, "url join")
		}
		us = append(us, u)
	}

	if err := client.PipelineGet(us, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error request response with status code %d", resp.StatusCode)
		}

		var csaf CSAF
		if err := json.NewDecoder(resp.Body).Decode(&csaf); err != nil {
			return errors.Wrap(err, "decode json")
		}

		t, err := time.Parse(time.RFC3339, csaf.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "failed to parse InitialReleaseDate option. expected: %q, actual: %q", time.RFC3339, csaf.Document.Tracking.InitialReleaseDate)
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)), csaf); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", csaf.Document.Tracking.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (o options) fetchIndex(client *utilhttp.Client) ([]string, error) {
	u, err := url.JoinPath(o.baseURL, "index.txt")
	if err != nil {
		return nil, errors.Wrap(err, "url join")
	}

	resp, err := client.Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var ls []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ls = append(ls, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "scanner encounter error")
	}

	return ls, nil
}
