package http

import (
	"bytes"
	stderrors "errors"
	"io"
	"net/http"
	"sync"
	"time"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
)

var defaultClient = NewClient()

type Client retryablehttp.Client

type clientOptions struct {
	httpClient   *http.Client
	logger       any
	retryWaitMin time.Duration
	retryWaitMax time.Duration
	retryMax     int
	checkRetry   retryablehttp.CheckRetry
	backoff      retryablehttp.Backoff
}

type ClientOption interface {
	apply(*clientOptions)
}

type clientHTTPClientOption struct {
	Client *http.Client
}

func (c clientHTTPClientOption) apply(opts *clientOptions) {
	// A nil client leaves the pooled default in place, so callers can
	// forward an optional *http.Client (e.g. a test server's client)
	// unconditionally instead of branching on it.
	if c.Client == nil {
		return
	}
	opts.httpClient = c.Client
}

func WithClientHTTPClient(client *http.Client) ClientOption {
	return clientHTTPClientOption{Client: client}
}

type clientLoggerOption struct {
	Log any
}

func (l clientLoggerOption) apply(opts *clientOptions) {
	opts.logger = l.Log
}

func WithClientLogger(log any) ClientOption {
	return clientLoggerOption{Log: log}
}

type clientRetryWaitMin struct {
	Wait time.Duration
}

func (w clientRetryWaitMin) apply(opts *clientOptions) {
	opts.retryWaitMin = w.Wait
}

func WithClientRetryWaitMin(wait time.Duration) ClientOption {
	return clientRetryWaitMin{Wait: wait}
}

type clientRetryWaitMax struct {
	Wait time.Duration
}

func (w clientRetryWaitMax) apply(opts *clientOptions) {
	opts.retryWaitMax = w.Wait
}

func WithClientRetryWaitMax(wait time.Duration) ClientOption {
	return clientRetryWaitMax{Wait: wait}
}

type clientRetryMax int

func (r clientRetryMax) apply(opts *clientOptions) {
	opts.retryMax = int(r)
}

func WithClientRetryMax(retry int) ClientOption {
	return clientRetryMax(retry)
}

type clientCheckRetry retryablehttp.CheckRetry

func (f clientCheckRetry) apply(opts *clientOptions) {
	opts.checkRetry = retryablehttp.CheckRetry(f)
}

func WithClientCheckRetry(f retryablehttp.CheckRetry) ClientOption {
	return clientCheckRetry(f)
}

type clientBackoff retryablehttp.Backoff

func (f clientBackoff) apply(opts *clientOptions) {
	opts.backoff = retryablehttp.Backoff(f)
}

func WithClientBackoff(f retryablehttp.Backoff) ClientOption {
	return clientBackoff(f)
}

func NewClient(opts ...ClientOption) *Client {
	options := &clientOptions{
		httpClient:   cleanhttp.DefaultPooledClient(),
		logger:       nil,
		retryWaitMin: 1 * time.Second,
		retryWaitMax: 30 * time.Second,
		retryMax:     4,
		checkRetry:   retryablehttp.ErrorPropagatedRetryPolicy,
		backoff:      retryablehttp.DefaultBackoff,
	}

	for _, o := range opts {
		o.apply(options)
	}

	return &Client{
		HTTPClient:   options.httpClient,
		Logger:       options.logger,
		RetryWaitMin: options.retryWaitMin,
		RetryWaitMax: options.retryWaitMax,
		RetryMax:     options.retryMax,
		CheckRetry:   options.checkRetry,
		Backoff:      options.backoff,
	}
}

type requestOptions struct {
	header http.Header
	body   []byte
}

type RequestOption interface {
	apply(*requestOptions)
}

type requestHeaderOption http.Header

func (h requestHeaderOption) apply(opts *requestOptions) {
	opts.header = http.Header(h)
}

func WithRequestHeader(h http.Header) RequestOption {
	return requestHeaderOption(h)
}

type requestBodyOption []byte

func (b requestBodyOption) apply(opts *requestOptions) {
	opts.body = b
}

func WithRequestBody(body []byte) RequestOption {
	return requestBodyOption(body)
}

func NewRequest(method, url string, opts ...RequestOption) (*retryablehttp.Request, error) {
	options := &requestOptions{
		header: nil,
		body:   nil,
	}

	for _, o := range opts {
		o.apply(options)
	}

	var body io.Reader
	if options.body != nil {
		body = bytes.NewReader(options.body)
	}

	r, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}
	r.Header = options.header

	rr, err := retryablehttp.FromRequest(r)
	if err != nil {
		return nil, errors.Wrap(err, "from request")
	}

	return rr, nil
}

func Get(url string, opts ...RequestOption) (*http.Response, error) {
	return defaultClient.Get(url, opts...)
}

func (c *Client) Get(url string, opts ...RequestOption) (*http.Response, error) {
	req, err := NewRequest(http.MethodGet, url, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}
	return c.Do(req)
}

func MultiGet(urls []string, concurrency int, wait time.Duration, noProgress bool, opts ...RequestOption) ([]*http.Response, error) {
	return defaultClient.MultiGet(urls, concurrency, wait, noProgress, opts...)
}

func (c *Client) MultiGet(urls []string, concurrency int, wait time.Duration, noProgress bool, opts ...RequestOption) ([]*http.Response, error) {
	resps := make([]*http.Response, 0, len(urls))

	respChan := make(chan *http.Response, len(urls))
	if err := c.PipelineGet(urls, concurrency, wait, noProgress, func(resp *http.Response) error { respChan <- resp; return nil }, opts...); err != nil {
		return nil, errors.Wrap(err, "pipeline get")
	}
	close(respChan)
	for r := range respChan {
		resps = append(resps, r)
	}
	return resps, nil
}

func (c *Client) PipelineGet(urls []string, concurrency int, wait time.Duration, noProgress bool, cont func(resp *http.Response) error, opts ...RequestOption) error {
	reqs := make([]*retryablehttp.Request, 0, len(urls))
	for _, u := range urls {
		req, err := NewRequest(http.MethodGet, u, opts...)
		if err != nil {
			return errors.Wrap(err, "new request")
		}
		reqs = append(reqs, req)
	}
	return c.PipelineDo(reqs, concurrency, wait, noProgress, cont)
}

func POST(url string, opts ...RequestOption) (*http.Response, error) {
	return defaultClient.POST(url, opts...)
}

func (c *Client) POST(url string, opts ...RequestOption) (*http.Response, error) {
	req, err := NewRequest(http.MethodPost, url, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}
	return c.Do(req)
}

func (c *Client) Do(req *retryablehttp.Request) (*http.Response, error) {
	resp, err := (*retryablehttp.Client)(c).Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "http request, url: %s", req.URL.Redacted())
	}

	return resp, nil
}

// maxPipelineErrors is how many failed requests PipelineDo's error names. A
// failed request does not stop the others, so the error can name every one,
// and that is what shows all of a source's broken files in one run. But a
// source that is down for the whole run fails thousands of requests the same
// way, so past this many the rest are only counted.
const maxPipelineErrors = 20

// PipelineDo makes the requests, at most concurrency of them at a time (a
// negative concurrency means no limit), and hands each response to cont. A
// request that fails, or whose continuation fails, does not stop the others.
// Once all are done, the error counts the ones that failed and names up to
// maxPipelineErrors of them.
func (c *Client) PipelineDo(reqs []*retryablehttp.Request, concurrency int, wait time.Duration, noProgress bool, cont func(resp *http.Response) error) error {
	// errgroup reads a negative limit as "no limit" and a positive one as
	// the limit itself, but gives zero an unbuffered semaphore, so the
	// first Go call blocks with nothing able to release it. Left alone, a
	// caller that passes zero hangs for as long as it has a request to
	// make, instead of failing.
	if concurrency == 0 {
		return errors.Errorf("unexpected concurrency. expected: %s, actual: %d", "a non-zero number", concurrency)
	}

	reqChan := make(chan *retryablehttp.Request)
	go func() {
		defer close(reqChan)
		for _, req := range reqs {
			reqChan <- req
		}
	}()

	bar := func() *progressbar.ProgressBar {
		if noProgress {
			return progressbar.DefaultSilent(int64(len(reqs)))
		}
		return progressbar.Default(int64(len(reqs)))
	}()

	// A failed request is traced by the URL it asked for, before any
	// redirect. Do's error already names it, but a continuation's error,
	// such as an unexpected status or a body that does not decode, does
	// not.
	do := func(req *retryablehttp.Request) error {
		resp, err := c.Do(req)
		if err != nil {
			return errors.Wrap(err, "do")
		}
		if err := cont(resp); err != nil {
			return errors.Wrapf(err, "continuation, url: %s", req.URL.Redacted())
		}
		return nil
	}

	var (
		mu   sync.Mutex
		errs []error
	)
	var g errgroup.Group
	g.SetLimit(concurrency)
	for req := range reqChan {
		g.Go(func() error {
			defer func() {
				time.Sleep(wait)
				_ = bar.Add(1)
			}()

			if err := do(req); err != nil {
				mu.Lock()
				defer mu.Unlock()
				errs = append(errs, err)
				return err
			}
			return nil
		})
	}
	// Wait returns only the first failure. But a Group without a context
	// runs every request whatever the others do, so by now errs holds every
	// failure.
	if err := g.Wait(); err != nil {
		if len(errs) > maxPipelineErrors {
			return errors.Wrapf(stderrors.Join(errs[:maxPipelineErrors]...), "%d of %d requests failed (first %d shown)", len(errs), len(reqs), maxPipelineErrors)
		}
		return errors.Wrapf(stderrors.Join(errs...), "%d of %d requests failed", len(errs), len(reqs))
	}

	_ = bar.Close()

	return nil
}
