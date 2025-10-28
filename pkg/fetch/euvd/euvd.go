package euvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://euvdservices.enisa.europa.eu/api/"

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "euvd"),
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

	log.Printf("[INFO] Fetch European Union Vulnerability Database(EUVD)")

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	ids, err := options.fetchEUVDIDs(client)
	if err != nil {
		return errors.Wrap(err, "fetch EUVD IDs")
	}

	if err := options.fetchEUVDs(client, ids); err != nil {
		return errors.Wrap(err, "fetch EUVDs")
	}

	return nil
}

func (opts options) fetchEUVDIDs(client *utilhttp.Client) ([]string, error) {
	log.Printf("[INFO] Fetch EUVD IDs")

	u, err := url.Parse(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "parse URL")
	}
	u = u.JoinPath("search")

	q := u.Query()
	q.Set("size", "1")
	q.Set("page", "0")
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		return nil, errors.Wrap(err, "fetch total")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var result search
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	var us []string
	for i := 0; i*100 < result.Total; i++ {
		q := u.Query()
		q.Set("size", "100")
		q.Set("page", fmt.Sprintf("%d", i))
		u.RawQuery = q.Encode()
		us = append(us, u.String())
	}

	var ids []string
	if err := client.PipelineGet(us, opts.concurrency, opts.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var result search
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, r := range result.Items {
			ids = append(ids, r.ID)
		}

		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "pipeline get")
	}

	return ids, nil
}

func (opts options) fetchEUVDs(client *utilhttp.Client, ids []string) error {
	log.Printf("[INFO] Fetch EUVDs")

	u, err := url.Parse(opts.baseURL)
	if err != nil {
		return errors.Wrap(err, "parse URL")
	}
	u = u.JoinPath("enisaid")

	us := make([]string, 0, len(ids))
	for _, id := range ids {
		q := u.Query()
		q.Set("id", id)
		u.RawQuery = q.Encode()
		us = append(us, u.String())
	}

	if err := client.PipelineGet(us, opts.concurrency, opts.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var a any
		if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
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
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
