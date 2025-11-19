package detail

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://euvdservices.enisa.europa.eu/api/enisaid"

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

func (r concurrencyOption) apply(opts *options) {
	opts.concurrency = int(r)
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

func Fetch(r io.Reader, opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "enisa", "euvd", "detail"),
		retry:       5,
		concurrency: 2,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch European Union Vulnerability Database(EUVD) Detail")
	if err := options.fetch(r); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (opts options) fetch(r io.Reader) error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry), utilhttp.WithClientCheckRetry(checkRetry))

	u, err := url.Parse(opts.baseURL)
	if err != nil {
		return errors.Wrap(err, "parse URL")
	}

	var us []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		id := scanner.Text()
		q := u.Query()
		q.Set("id", id)
		u.RawQuery = q.Encode()
		us = append(us, u.String())
	}
	if err := scanner.Err(); err != nil {
		return errors.Wrap(err, "scanner encounter error")
	}

	if err := client.PipelineGet(us, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var a any
			if err := json.UnmarshalRead(resp.Body, &a); err != nil {
				return errors.Wrap(err, "decode json")
			}

			ss, err := util.Split(resp.Request.URL.Query().Get("id"), "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "EUVD-yyyy-\\d{4,}", resp.Request.URL.Query().Get("id"))
			}

			if err := util.Write(filepath.Join(opts.dir, ss[1], fmt.Sprintf("%s.json", resp.Request.URL.Query().Get("id"))), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, ss[1], fmt.Sprintf("%s.json", resp.Request.URL.Query().Get("id"))))
			}

			return nil
		case http.StatusNoContent:
			log.Printf("[WARN] %s may have been deleted", resp.Request.URL.Query().Get("id"))
			return nil
		default:
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if shouldRetry, err := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err); shouldRetry {
		return shouldRetry, errors.Wrap(err, "retry policy")
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return false, nil
	case http.StatusForbidden:
		return true, errors.Errorf("unexpected HTTP status %s", resp.Status)
	default:
		return false, errors.Errorf("unexpected HTTP status %s", resp.Status)
	}
}
