package cve

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"

	"github.com/pkg/errors"

	"io"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const (
	// API reference page: https://nvd.nist.gov/developers/vulnerabilities
	baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// Should be <= 2,000
	keyResultsPerPage = "resultsPerPage"
	// So this implementation uses the max value
	resulstPerPageMax = 2_000

	// 0-origin index of results.
	// When the request with startIndex=100 and resultsPerPage in the corresponding response is 2000,
	// the next request should have startIndex=2100.
	keyStartInedex = "startIndex"
)

type options struct {
	baseURL        string
	resultsPerPage int
	apiKey         string
	dir            string
	retry          int
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
		baseURL:        baseURL,
		resultsPerPage: resulstPerPageMax,
		//  TODO(shino): Where to put the default value, cmd/fetch/fetch.go or here?
		dir:   filepath.Join(util.SourceDir(), "nvd", "api", "cve"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	url, err := url.Parse(options.baseURL)
	if err != nil {
		return errors.Wrapf(err, "parse base URL: %s", options.baseURL)
	}
	startIndex := 0
	//  TODO(shino): prevent infinite loop by any accidents
	for {
		resultsPerPage, err := callAPI(options, url, startIndex)
		if err != nil {
			return errors.Wrap(err, "call NVD CVE API")
		}
		if resultsPerPage == 0 {
			// Last page reached
			return nil
		}

		startIndex += resultsPerPage
		//  TODO(shino): sleep to secure the API rate limit
	}
}

func callAPI(opts *options, url *url.URL, startIndex int) (int, error) {

	log.Printf("[DEBUG] About to call NVD API CVE with startIndex=%d", startIndex)
	q := url.Query()
	q.Set(keyStartInedex, strconv.Itoa(startIndex))
	// q.Set(keyResultsPerPage, strconv.Itoa(opts.resultsPerPage))
	q.Set(keyResultsPerPage, strconv.Itoa(1))
	url.RawQuery = q.Encode()

	c := &http.Client{}
	r, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return 0, errors.Wrapf(err, "new HTTP Request: %s", url.String())
	}
	h := r.Header
	h.Add("api-key", opts.apiKey)

	resp, err := c.Do(r)
	if err != nil {
		return 0, errors.Wrapf(err, "Get URL: %s", url.String())
	}

	defer resp.Body.Close()

	// fmt.Printf("%+v", resp)

	if resp.StatusCode != http.StatusOK {
		return 0, errors.Errorf("Error request response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, errors.Wrap(err, "read response body")
	}

	var cveAPI20 CVEAPI20
	if err := json.Unmarshal(bs, &cveAPI20); err != nil {
		return 0, errors.Wrapf(err, "unmarshal NVE API CVE with startIndex=%d", startIndex)
	}

	//  TODO(shino): temporal
	cveAPI20.Vulnerabilities = cveAPI20.Vulnerabilities[0:1]
	fmt.Printf("%#v\n", cveAPI20)
	return 0, nil
}
