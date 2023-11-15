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
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	apiURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// resultsPerPage must be <= 2,000, this implementation almost uses the max value
	resultsPerPageMax = 2_000
)

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
	apiKey      string

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

type apiKeyOption string

func (a apiKeyOption) apply(opts *options) {
	opts.apiKey = string(a)
}

func WithAPIKey(apiKey string) Option {
	return apiKeyOption(apiKey)
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
		baseURL:        apiURL,
		apiKey:         "",
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

	log.Printf("[INFO] Fetch NVD CVE API. dir: %s", options.dir)

	checkRetry := func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		// do not retry on context.Canceled or context.DeadlineExceeded
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil {
			return false, errors.Wrap(err, "http client Do")
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

	c := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry))

	h := make(http.Header)
	if options.apiKey != "" {
		h.Add("apiKey", options.apiKey)
	}
	headerOption := utilhttp.WithRequestHeader(h)

	// Preliminary API call to get totalResults.
	// Use 1 as resultsPerPage to save time.
	u, err := fullURL(options.baseURL, 0, 1)
	if err != nil {
		return errors.Wrap(err, "full URL")
	}
	bs, err := c.Get(u, headerOption)
	if err != nil {
		return errors.Wrap(err, "preliminary API call")
	}
	var preliminary api20
	if err := json.Unmarshal(bs, &preliminary); err != nil {
		return errors.Wrap(err, "unmarshal json")
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

	nextTask := func(bs []byte) error {
		var response api20
		if err := json.Unmarshal(bs, &response); err != nil {
			return errors.Wrap(err, "unmarshal json")
		}

		// Sanity check:
		// NVD's API document does not say that response item counts are equal to
		// request's resultsPerPage (in non-final pages).
		// If we don't check the counts, we may have incomplete results.
		actualResults := len(response.Vulnerabilities)
		finalStartIndex := options.resultsPerPage * (pages - 1)
		if response.StartIndex == finalStartIndex && !preciselyPaged {
			// Allow the last page have more than expected results,
			// because item may be added in the middle of command execution.
			expectedResults := totalResults % options.resultsPerPage
			if actualResults < expectedResults {
				return errors.Errorf("unexpected results at last page, startIndex: %d, expected: %d actual: %d", response.StartIndex, expectedResults, actualResults)
			}
		} else {
			// Non-final page or fully-populated final page, should have max count.
			if actualResults != options.resultsPerPage {
				return errors.Errorf("unexpected results at startIndex: %d, expected: %d actual: %d", response.StartIndex, options.resultsPerPage, actualResults)
			}
		}

		for _, v := range response.Vulnerabilities {
			splitted, err := util.Split(v.CVE.ID, "-", "-")
			if err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVE.ID)
				continue
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVE.ID)
				continue
			}

			if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVE.ID)))
			}
		}
		return nil
	}
	if err := c.PipelineGet(us, options.concurrency, options.wait, nextTask, headerOption); err != nil {
		return errors.Wrap(err, "pipeline get")
	}
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
