package list

import (
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
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://euvdservices.enisa.europa.eu/api/search"

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

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "enisa", "euvd", "list"),
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

	log.Printf("[INFO] Fetch European Union Vulnerability Database(EUVD) List")
	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (opts options) fetch() error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry), utilhttp.WithClientCheckRetry(checkRetry))

	u, err := url.Parse(opts.baseURL)
	if err != nil {
		return errors.Wrap(err, "parse URL")
	}

	bar := progressbar.Default(-1, "Paging EUVD List")
	g, _ := errgroup.WithContext(context.TODO())
	g.SetLimit(opts.concurrency)
	for i := 0; i < opts.concurrency; i++ {
		g.Go(func() error {
			for p := i; ; p += opts.concurrency {
				q := u.Query()
				q.Set("size", "100")
				q.Set("page", fmt.Sprintf("%d", p))
				u.RawQuery = q.Encode()

				resp, err := client.Get(u.String())
				if err != nil {
					return errors.Wrap(err, "fetch")
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					_, _ = io.Copy(io.Discard, resp.Body)
					return errors.Errorf("error response with status code %d", resp.StatusCode)
				}

				var res response
				if err := json.UnmarshalRead(resp.Body, &res); err != nil {
					return errors.Wrap(err, "decode json")
				}

				if len(res.Items) == 0 {
					return nil
				}

				for _, item := range res.Items {
					ss, err := util.Split(item.ID, "-", "-")
					if err != nil {
						return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "EUVD-yyyy-\\d{4,}", item.ID)
					}

					if err := util.Write(filepath.Join(opts.dir, ss[1], fmt.Sprintf("%s.json", item.ID)), item); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, ss[1], fmt.Sprintf("%s.json", item.ID)))
					}
				}

				time.Sleep(opts.wait)
				_ = bar.Add(1)
			}
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	_ = bar.Close()

	return nil
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if shouldRetry, err := retryablehttp.ErrorPropagatedRetryPolicy(ctx, resp, err); shouldRetry {
		return shouldRetry, errors.Wrap(err, "retry policy")
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return false, nil
	case http.StatusForbidden:
		return true, errors.Errorf("unexpected HTTP status %s", resp.Status)
	default:
		return false, errors.Errorf("unexpected HTTP status %s", resp.Status)
	}
}
