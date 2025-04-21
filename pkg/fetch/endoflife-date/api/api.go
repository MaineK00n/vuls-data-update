package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://endoflife.date/api/"

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "endoflife-date", "api"),
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

	log.Println("[INFO] Fetch endoflife.date API")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	ps, err := options.fetchAllProducts(client)
	if err != nil {
		return errors.Wrap(err, "fetch index")
	}

	header := make(http.Header)
	header.Set("Accept", "application/json")

	reqs := make([]*retryablehttp.Request, 0, len(ps))
	for _, p := range ps {
		u, err := url.JoinPath(options.baseURL, fmt.Sprintf("%s.json", p))
		if err != nil {
			return errors.Wrap(err, "url join")
		}

		req, err := utilhttp.NewRequest(http.MethodGet, u, utilhttp.WithRequestHeader(header))
		if err != nil {
			return errors.Wrap(err, "new request")
		}
		reqs = append(reqs, req)
	}

	if err := client.PipelineDo(reqs, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var cycles []Cycle
		if err := json.NewDecoder(resp.Body).Decode(&cycles); err != nil {
			return errors.Wrap(err, "decode json")
		}

		if err := util.Write(filepath.Join(options.dir, path.Base(resp.Request.URL.Path)), cycles); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, path.Base(resp.Request.URL.Path)))
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline do")
	}

	return nil
}

func (o options) fetchAllProducts(client *utilhttp.Client) ([]string, error) {
	u, err := url.JoinPath(o.baseURL, "all.json")
	if err != nil {
		return nil, errors.Wrap(err, "url join")
	}

	header := make(http.Header)
	header.Set("Accept", "application/json")

	req, err := utilhttp.NewRequest(http.MethodGet, u, utilhttp.WithRequestHeader(header))
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var ps []string
	if err := json.NewDecoder(resp.Body).Decode(&ps); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	return ps, nil
}
