package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/cheggaaa/pb/v3"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

var defaultClient = NewClient()

type Client retryablehttp.Client

type clientOptions struct {
	httpClient   *http.Client
	logger       interface{}
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
	opts.httpClient = c.Client
}

func WithClientHTTPClient(client *http.Client) ClientOption {
	return clientHTTPClientOption{Client: client}
}

type clientLoggerOption struct {
	Log interface{}
}

func (l clientLoggerOption) apply(opts *clientOptions) {
	opts.logger = l.Log
}

func WithClientLogger(log interface{}) ClientOption {
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
		checkRetry:   retryablehttp.DefaultRetryPolicy,
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

func MultiGet(urls []string, concurrency, wait int, opts ...RequestOption) ([]*http.Response, error) {
	return defaultClient.MultiGet(urls, concurrency, wait, opts...)
}

func (c *Client) MultiGet(urls []string, concurrency, wait int, opts ...RequestOption) ([]*http.Response, error) {
	resps := make([]*http.Response, 0, len(urls))

	respChan := make(chan *http.Response, len(urls))
	if err := c.PipelineGet(urls, concurrency, wait, func(resp *http.Response) error { respChan <- resp; return nil }, opts...); err != nil {
		return nil, errors.Wrap(err, "pipeline get")
	}
	close(respChan)
	for r := range respChan {
		resps = append(resps, r)
	}
	return resps, nil
}

func (c *Client) PipelineGet(urls []string, concurrency, wait int, cont func(resp *http.Response) error, opts ...RequestOption) error {
	reqs := make([]*retryablehttp.Request, 0, len(urls))
	for _, u := range urls {
		req, err := NewRequest(http.MethodGet, u, opts...)
		if err != nil {
			return errors.Wrap(err, "new request")
		}
		reqs = append(reqs, req)
	}
	return c.PipelineDo(reqs, concurrency, wait, cont)
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

func (c *Client) PipelineDo(reqs []*retryablehttp.Request, concurrency, wait int, cont func(resp *http.Response) error) error {
	reqChan := make(chan *retryablehttp.Request)
	go func() {
		defer close(reqChan)
		for _, req := range reqs {
			reqChan <- req
		}
	}()

	bar := pb.Full.Start(len(reqs))
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(concurrency)
	for req := range reqChan {
		req := req
		g.Go(func() error {
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
				bar.Increment()
				time.Sleep(time.Duration(wait) * time.Second)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	bar.Finish()
	return nil
}
