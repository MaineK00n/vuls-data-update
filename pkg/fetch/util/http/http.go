package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
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
	httpClient     *http.Client
	logger         any
	retryWaitMin   time.Duration
	retryWaitMax   time.Duration
	retryMax       int
	checkRetry     retryablehttp.CheckRetry
	backoff        retryablehttp.Backoff
	allowPlainHTTP bool
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

type clientAllowPlainHTTP bool

func (a clientAllowPlainHTTP) apply(opts *clientOptions) {
	opts.allowPlainHTTP = bool(a)
}

// WithClientAllowPlainHTTP lets the client send requests over plain http,
// which it otherwise refuses, redirects included. A fetcher checks no
// signature on what it stores, so it takes as it comes a response anyone on
// the path can rewrite. The option is for an upstream that serves nothing over
// https, given at the call that talks to it.
func WithClientAllowPlainHTTP(allow bool) ClientOption {
	return clientAllowPlainHTTP(allow)
}

// NewClient returns a client that retries a failed request and, unless
// WithClientAllowPlainHTTP says otherwise, refuses to send one over plain http.
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

	httpClient, checkRetry := options.httpClient, options.checkRetry
	if !options.allowPlainHTTP {
		httpClient, checkRetry = httpsOnly(options.httpClient, options.checkRetry)
	}

	return &Client{
		HTTPClient:   httpClient,
		Logger:       options.logger,
		RetryWaitMin: options.retryWaitMin,
		RetryWaitMax: options.retryWaitMax,
		RetryMax:     options.retryMax,
		CheckRetry:   checkRetry,
		Backoff:      options.backoff,
	}
}

// errPlainHTTP is the error of a request a client refuses to send over plain
// http.
var errPlainHTTP = errors.New("plain http request refused")

// httpsOnly returns a copy of client that refuses to send a request over plain
// http, and a retry policy that does not retry the refusal, which every retry
// would meet again. The copy leaves client itself, which a test may hand to
// several clients, as it was.
func httpsOnly(client *http.Client, checkRetry retryablehttp.CheckRetry) (*http.Client, retryablehttp.CheckRetry) {
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	c := *client
	c.Transport = httpsOnlyTransport{base: base}

	return &c, func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if errors.Is(err, errPlainHTTP) {
			return false, err
		}
		return checkRetry(ctx, resp, err)
	}
}

// httpsOnlyTransport refuses a request over plain http. An http.Client sends
// every request through its transport, so a redirect to plain http is refused
// as well.
type httpsOnlyTransport struct {
	base http.RoundTripper
}

func (t httpsOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		// A RoundTripper closes the body even when it fails. Like the
		// transport of net/http, which does so for a scheme it does not
		// support, it has the request's own error to return, not Close's.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errPlainHTTP
	}
	return t.base.RoundTrip(req)
}

// CloseIdleConnections passes on to the base transport the call that
// http.Client.CloseIdleConnections, which retryablehttp makes after a failed
// request, can only make on a transport that has the method.
func (t httpsOnlyTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
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
		return nil, errors.Wrapf(err, "http request, url: %s", req.URL.String())
	}

	return resp, nil
}

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

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(concurrency)
	for req := range reqChan {
		g.Go(func() error {
			defer func() {
				time.Sleep(wait)
				_ = bar.Add(1)
			}()

			resp, err := c.Do(req)
			if err != nil {
				return errors.Wrapf(err, "do %#v", req)
			}
			if err := cont(resp); err != nil {
				return errors.Wrapf(err, "continuation %#v", resp)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}

	_ = bar.Close()

	return nil
}
