package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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
	wait        int
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

type waitOption int

func (r waitOption) apply(opts *options) {
	opts.wait = int(r)
}

func WithWait(wait int) Option {
	return waitOption(wait)
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
		baseURL: apiURL,
		apiKey:  "",
		//  TODO(shino): Where to put the default value, cmd/fetch/fetch.go or here?
		dir:   filepath.Join(util.CacheDir(), "nvd", "api", "cve"),
		retry: 3,
	}
	for _, o := range opts {
		o.apply(options)
	}
	log.Printf("[INFO] Fetch NVD API CVE start, dir=%s", options.dir)

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch NVD API CVE base URL: %s", options.baseURL)
	c := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry))

	h := http.Header{}
	if strings.Compare(options.apiKey, "") != 0 {
		h.Add("apiKey", options.apiKey)
	}
	headerOption := utilhttp.WithRequestHeader(h)

	// Preliminary API call to get totalResults
	// Use 1 as resultsPerPage to save time
	url, err := fullURL(options.baseURL, 0, 1)
	if err != nil {
		return errors.Wrap(err, "Generate full URL")
	}
	log.Printf("url: %s", url)
	bs, err := c.Get(url, headerOption)
	if err != nil {
		return errors.Wrap(err, "call NVD CVE API")
	}
	var preliminary CVEAPI20
	if err := json.Unmarshal(bs, &preliminary); err != nil {
		return errors.Wrapf(err, "unmarshal NVE API CVE, %s", bs)
	}
	preciselyPaged := (preliminary.TotalResults % resultsPerPageMax) == 0
	var pages int
	if preciselyPaged {
		pages = preliminary.TotalResults / resultsPerPageMax
	} else {
		pages = preliminary.TotalResults/resultsPerPageMax + 1
	}
	log.Printf("[INFO] total results=%d, pages=%d", preliminary.TotalResults, pages)

	// Actual API calls
	urls := make([]string, 0, preliminary.TotalResults/resultsPerPageMax+1)
	for startIndex := 0; startIndex < preliminary.TotalResults; startIndex += resultsPerPageMax {
		url, err := fullURL(options.baseURL, startIndex, resultsPerPageMax)
		if err != nil {
			return errors.Wrap(err, "Generate full URL")
		}
		urls = append(urls, url)
	}

	log.Printf("[INFO] Call API: wait=%d [sec], concurrency=%d", options.wait, options.concurrency)
	bsList, err := c.MultiGet(urls, options.concurrency, options.wait, headerOption)
	if err != nil {
		return errors.Wrap(err, "NVD API CVE MultiGet")
	}

	log.Printf("[INFO] API calls finished, about to write files")
	bar := pb.StartNew(int(pages))
	for _, bs := range bsList {
		if err := write(options.dir, bs, resultsPerPageMax, preliminary.TotalResults, pages, preciselyPaged); err != nil {
			return err
		}
		bar.Increment()
	}
	bar.Finish()

	log.Printf("[INFO] Fetch NVD API CVE finished")
	return nil
}

func fullURL(baseURL string, startIndex, resultsPerPage int) (string, error) {
	url, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.Wrapf(err, "parse base URL: %s", baseURL)
	}
	q := url.Query()
	q.Set(keyStartInedex, strconv.Itoa(startIndex))
	q.Set(keyResultsPerPage, strconv.Itoa(resultsPerPageMax))
	url.RawQuery = q.Encode()
	return url.String(), nil
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// NVD JSON API returns 403 in rate limit excesses, should retry.
	// Also, the API returns 408 infreqently.
	if resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusRequestTimeout {
		log.Printf("[INFO] HTTP %d happened, may retry", resp.StatusCode)
		return true, nil
	}

	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

func write(dir string, bs []byte, resultsPerPage, totalResults, pages int, preciselyPaged bool) error {

	var cveAPI20 CVEAPI20
	if err := json.Unmarshal(bs, &cveAPI20); err != nil {
		return errors.Wrapf(err, "unmarshal NVE API CVE with raw JSON=%s", bs)
	}

	// Sanity check
	finalStartIndex := resultsPerPageMax * (pages - 1)
	var expectedResults int
	if cveAPI20.StartIndex == finalStartIndex {
		if preciselyPaged {
			expectedResults = resultsPerPage
		} else {
			expectedResults = totalResults % resultsPerPage
		}
	} else {
		expectedResults = resultsPerPage
	}
	actualResults := len(cveAPI20.Vulnerabilities)
	if expectedResults != actualResults {
		return errors.Errorf("Unexpected result count at startIndex=%d, expected=%d actual=%d",
			cveAPI20.StartIndex, expectedResults, actualResults)
	}

	for _, v := range cveAPI20.Vulnerabilities {
		// ID is like "CVE-2023-24479"
		tokens := strings.Split(v.CVE.ID, "-")
		if len(tokens) < 3 {
			errors.Errorf("unexpected CVE.ID format: %#v", v)
		}
		year := tokens[1]
		path := filepath.Join(dir, year, fmt.Sprintf("%s.json", v.CVE.ID))
		if err := util.Write(path, v); err != nil {
			return errors.Wrapf(err, "write %s", path)
		}
	}
	return nil
}
