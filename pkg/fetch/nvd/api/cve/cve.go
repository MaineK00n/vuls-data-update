package cve

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// Should be <= 2,000
	keyResultsPerPage = "resultsPerPage"
	// So this implementation uses the max value
	resultsPerPageMax = 2_000

	// 0-origin index of results.
	// When the request with startIndex=100 and resultsPerPage in the corresponding response is 2000,
	// the next request should have startIndex=2100.
	keyStartInedex = "startIndex"
)

type options struct {
	baseURL     string
	apiKey      string
	interval    int
	concurrency int
	dir         string
	retry       int
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

type apiKeyOption string

func (a apiKeyOption) apply(opts *options) {
	opts.apiKey = string(a)
}

func WithAPIKey(apiKey string) Option {
	return apiKeyOption(apiKey)
}

type intervalOption int

func (r intervalOption) apply(opts *options) {
	opts.interval = int(r)
}

func WithInterval(interval int) Option {
	return intervalOption(interval)
}

type concurrencyOption int

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
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
		apiKey:  "",
		//  TODO(shino): Where to put the default value, cmd/fetch/fetch.go or here?
		dir:   filepath.Join(util.CacheDir(), "nvd", "api", "cve"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch NVD API CVE base URL: %s", options.baseURL)

	h := http.Header{}
	if strings.Compare(options.apiKey, "") != 0 {
		h.Add("apiKey", options.apiKey)
	}
	headerOption := utilhttp.WithRequestHeader(h)

	checkRetry := func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		// do not retry on context.Canceled or context.DeadlineExceeded
		if ctx.Err() != nil {
			return false, ctx.Err()
		}

		// NVD JSON API returns 403 in rate limit excesses, should retry
		if resp.StatusCode == http.StatusForbidden {
			// log.Printf("[INFO] HTTP %d happened, may retry", resp.StatusCode)
			return true, nil
		}

		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}
	c := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry),
		utilhttp.WithClientCheckRetry(checkRetry))

	// Preliminary API call to get totalResults
	//  TODO(shino): it's waste of time in single goroutine case
	url, err := fullURL(options.baseURL, 0, 1)
	if err != nil {
		return errors.Wrap(err, "Generate full URL")
	}

	bs, err := c.Get(url, headerOption)
	if err != nil {
		return errors.Wrap(err, "call NVD CVE API")
	}
	var result CVEAPI20
	if err := json.Unmarshal(bs, &result); err != nil {
		return errors.Wrapf(err, "unmarshal NVE API CVE, %s", bs)
	}

	pages := result.TotalResults/resultsPerPageMax + 1
	log.Printf("[INFO] total results=%d, pages=%d", result.TotalResults, pages)

	urls := make([]string, 0, result.TotalResults/resultsPerPageMax+1)
	var startIndex int64
	// result.TotalResults = 5000
	for startIndex = 0; startIndex < result.TotalResults; startIndex += resultsPerPageMax {
		url, err := fullURL(options.baseURL, startIndex, resultsPerPageMax)
		if err != nil {
			return errors.Wrap(err, "Generate full URL")
		}
		urls = append(urls, url)
	}

	log.Printf("[INFO] GET interval=%d [sec], concurrency=%d", options.interval, options.concurrency)
	bsList, err := c.MultiGet(urls, options.interval, options.concurrency, headerOption)
	if err != nil {
		return errors.Wrap(err, "NVD API CVE MultiGet")
	}

	//  TODO(shino): NIY
	write(bsList[0])
	log.Printf("[INFO] Fetch NVD API CVE finished")
	return nil
}

func fullURL(baseUrl string, startIndex, resultsPerPage int64) (string, error) {
	url, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.Wrapf(err, "parse base URL: %s", baseURL)
	}
	q := url.Query()
	q.Set(keyStartInedex, strconv.FormatInt(startIndex, 10))
	q.Set(keyResultsPerPage, strconv.FormatInt(resultsPerPageMax, 10))
	url.RawQuery = q.Encode()
	return url.String(), nil
}

func write(bs []byte) error {

	// fmt.Printf("bs: %s\n", bs)

	var cveAPI20 CVEAPI20
	if err := json.Unmarshal(bs, &cveAPI20); err != nil {
		return errors.Wrapf(err, "unmarshal NVE API CVE with raw JSON=%s", bs)
	}

	//  TODO(shino): write
	cveAPI20.Vulnerabilities = cveAPI20.Vulnerabilities[0:1]
	return nil
}
