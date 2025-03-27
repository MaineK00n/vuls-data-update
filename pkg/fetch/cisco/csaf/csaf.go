package csaf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURLFormat = "https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/%s/csaf/%s.json"

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

func Fetch(ids []string, opts ...Option) error {
	options := &options{
		dataURL:     dataURLFormat,
		dir:         filepath.Join(util.CacheDir(), "fetch", "cisco", "csaf"),
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

	log.Printf("[INFO] Fetch Cisco Security Advisories (CSAF). dir: %s", options.dir)

	us := make([]string, 0, len(ids))
	for _, id := range ids {
		us = append(us, fmt.Sprintf(options.dataURL, id, id))
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry))
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

		t, err := time.Parse("2006-01-02T15:04:05-07:00", csaf.Document.Tracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "unexpected published format. expected: %q, actual: %q", "2006-01-02T15:04:05-07:00", csaf.Document.Tracking.InitialReleaseDate)
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

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if shouldRetry, err := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err); shouldRetry {
		return shouldRetry, errors.Wrap(err, "retry policy")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, errors.Wrap(err, "read all response body")
	}

	var csaf CSAF
	if err := json.Unmarshal(body, &csaf); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return true, errors.Wrap(syntaxErr, "unmarshal json")
		}
		return false, errors.Wrap(err, "unmarshal json")
	}

	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return false, nil
}
