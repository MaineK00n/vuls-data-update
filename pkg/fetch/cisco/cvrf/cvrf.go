package cvrf

import (
	"bytes"
	"context"
	"encoding/xml"
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

const dataURLFormat = "https://sec.cloudapps.cisco.com/security/center/contentxml/CiscoSecurityAdvisory/%s/cvrf/%s_cvrf.xml"

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
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

func Fetch(ids []string, opts ...Option) error {
	options := &options{
		dataURL:     dataURLFormat,
		dir:         filepath.Join(util.CacheDir(), "fetch", "cisco", "cvrf"),
		retry:       3,
		concurrency: 5,
		wait:        1 * time.Second,
	}
	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Cisco Security Advisories (CVRF). dir: %s", options.dir)

	us := make([]string, 0, len(ids))
	for _, id := range ids {
		us = append(us, fmt.Sprintf(options.dataURL, id, id))
	}

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry), utilhttp.WithClientCheckRetry(checkRetry))
	if err := client.PipelineGet(us, options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var cvrf CVRF
		if err := xml.NewDecoder(resp.Body).Decode(&cvrf); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		t, err := time.Parse("2006-01-02T15:04:05", cvrf.DocumentTracking.InitialReleaseDate)
		if err != nil {
			return errors.Wrapf(err, "unexpected published format. expected: %q, actual: %q", "2006-01-02T15:04:05", cvrf.DocumentTracking.InitialReleaseDate)
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", cvrf.DocumentTracking.Identification.ID)), cvrf); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", cvrf.DocumentTracking.Identification.ID)))
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

	var cvrf CVRF
	if err := xml.Unmarshal(body, &cvrf); err != nil {
		if errors.Is(err, io.EOF) {
			return true, errors.Wrap(err, "unmarshal xml")
		}
		return false, errors.Wrap(err, "unmarshal xml")
	}

	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	return false, nil
}
