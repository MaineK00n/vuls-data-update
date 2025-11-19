package vulns

import (
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

const baseURL = "https://www.variotdbs.pl/api/vulns"

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

func Fetch(apiToken string, opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "variot", "vulns"),
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

	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))
	headerOption := utilhttp.WithRequestHeader(http.Header{"Authorization": []string{fmt.Sprintf("Token %s", apiToken)}})

	log.Println("[INFO] Fetch VARIoT Vulns")
	if err := options.fetch(client, headerOption); err != nil {
		return errors.Wrap(err, "fetch variot vulns")
	}

	return nil
}

func (opts options) fetch(client *utilhttp.Client, header utilhttp.RequestOption) error {
	u, err := url.Parse(opts.baseURL)
	if err != nil {
		return errors.Wrap(err, "url parse")
	}

	q := u.Query()
	q.Set("jsonld", "false")
	q.Set("limit", "1")
	q.Set("offset", "0")
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String(), header)
	if err != nil {
		return errors.Wrap(err, "fetch vulns")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r vulns
	if err := json.UnmarshalRead(resp.Body, &r); err != nil {
		return errors.Wrap(err, "decode json")
	}

	var reqs []*retryablehttp.Request
	for i := 0; i < r.Count; i += 100 {
		q := u.Query()
		q.Set("jsonld", "false")
		q.Set("limit", "100")
		q.Set("offset", fmt.Sprintf("%d", i))
		u.RawQuery = q.Encode()

		req, err := utilhttp.NewRequest(http.MethodGet, u.String(), header)
		if err != nil {
			return errors.Wrap(err, "new request")
		}
		reqs = append(reqs, req)
	}

	if err := client.PipelineDo(reqs, opts.concurrency, opts.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var vs vulns
		if err := json.UnmarshalRead(resp.Body, &vs); err != nil {
			return errors.Wrap(err, "decode json")
		}

		for _, v := range vs.Results {
			ss, err := util.Split(v.ID, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "VAR-<YEARMONTH>-<ENUMERATOR>", v.ID)
			}

			t, err := time.Parse("200601", ss[1])
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "VAR-<YEARMONTH>-<ENUMERATOR>", v.ID)
			}

			if err := util.Write(filepath.Join(opts.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", v.ID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", v.ID)))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}
