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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// resultsPerPage must be <= 2,000, this implementation almost uses the max value
	resultsPerPageMax = 2_000
)

type options struct {
	baseURL     string
	apiKey      string
	wait        int
	concurrency int
	dir         string
	retry       int

	// test purpose only
	resultsPerPage int
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

type resultsPerPageOption int

func (r resultsPerPageOption) apply(opts *options) {
	opts.resultsPerPage = int(r)
}

func WithResultsPerPage(resultsPerPage int) Option {
	return resultsPerPageOption(resultsPerPage)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL: apiURL,
		apiKey:  "",
		//  TODO(shino): Where to put the default value, cmd/fetch/fetch.go or here?
		dir:            filepath.Join(util.CacheDir(), "nvd", "api", "cve"),
		retry:          3,
		resultsPerPage: resultsPerPageMax,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch start, dir: %s", options.dir)

	c := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry))

	h := make(http.Header)
	if options.apiKey != "" {
		h.Add("apiKey", options.apiKey)
	}
	headerOption := utilhttp.WithRequestHeader(h)

	// Preliminary API call to get totalResults
	// Use 1 as resultsPerPage to save time
	u, err := fullURL(options.baseURL, 0, 1)
	if err != nil {
		return errors.Wrap(err, "full URL")
	}
	bs, err := c.Get(u, headerOption)
	if err != nil {
		return errors.Wrap(err, "preliminary API call")
	}
	var preliminary API20
	if err := json.Unmarshal(bs, &preliminary); err != nil {
		return errors.Wrap(err, "unmarshal")
	}
	totalResults := preliminary.TotalResults
	preciselyPaged := (totalResults % options.resultsPerPage) == 0
	pages := totalResults / options.resultsPerPage
	if !preciselyPaged {
		pages++
	}

	// Actual API calls
	us := make([]string, 0, pages)
	for startIndex := 0; startIndex < totalResults; startIndex += options.resultsPerPage {
		url, err := fullURL(options.baseURL, startIndex, options.resultsPerPage)
		if err != nil {
			return errors.Wrap(err, "full URL")
		}
		us = append(us, url)
	}

	bsList, err := c.MultiGet(us, options.concurrency, options.wait, headerOption)
	if err != nil {
		return errors.Wrap(err, "MultiGet")
	}

	log.Printf("[INFO] API calls finished, about to write files")
	bar := pb.StartNew(int(pages))
	for _, bs := range bsList {
		if err := write(options.dir, bs, options.resultsPerPage, totalResults, pages, preciselyPaged); err != nil {
			return errors.Wrap(err, "write")
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func fullURL(baseURL string, startIndex, resultsPerPage int) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", errors.Wrapf(err, "parse base URL: %s", baseURL)
	}
	q := u.Query()
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	// do not retry on context.Canceled or context.DeadlineExceeded
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	// NVD JSON API returns 403 in rate limit excesses, should retry.
	// Also, the API returns 408 infreqently.
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusRequestTimeout:
		log.Printf("[INFO] HTTP %d happened, may retry", resp.StatusCode)
		return true, nil
	}

	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}

func write(dir string, bs []byte, resultsPerPage, totalResults, pages int, preciselyPaged bool) error {

	var cveAPI20 API20
	if err := json.Unmarshal(bs, &cveAPI20); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	// Sanity check
	finalStartIndex := resultsPerPage * (pages - 1)
	expectedResults := resultsPerPage
	if cveAPI20.StartIndex == finalStartIndex && !preciselyPaged {
		expectedResults = totalResults % resultsPerPage
	}
	actualResults := len(cveAPI20.Vulnerabilities)
	if expectedResults != actualResults {
		return errors.Errorf("unexpected results at startIndex: %d, expected: %d actual: %d", cveAPI20.StartIndex, expectedResults, actualResults)
	}

	for _, v := range cveAPI20.Vulnerabilities {
		splitted, err := util.Split(v.CVE.ID, "-", "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVE.ID)
			continue
		}
		year := splitted[1]
		if err := util.Write(filepath.Join(dir, year, fmt.Sprintf("%s.json", v.CVE.ID)), v); err != nil {
			return errors.Wrapf(err, "write, path: %s", filepath.Join(dir, year, fmt.Sprintf("%s.json", v.CVE.ID)))
		}
	}
	return nil
}
