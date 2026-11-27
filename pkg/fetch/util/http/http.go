package http

import (
	"bytes"
	"context"
	stderrors "errors"
	"io"
	"net/http"
	"os"
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
	bufferBody   bool
	spoolBody    bool
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

type clientBufferBody bool

func (b clientBufferBody) apply(opts *clientOptions) {
	opts.bufferBody = bool(b)
}

// WithClientBufferBody has the client read each response body whole before it
// returns the response. A body cut off partway, as by a connection reset, then
// fails the request within the retry loop and is asked for again, where it
// would otherwise fail whatever reads the body. Each body is held in memory, and
// a response streamed or upgraded is not handed on until it ends, so it is for
// clients whose responses are documents of modest size.
func WithClientBufferBody(buffer bool) ClientOption {
	return clientBufferBody(buffer)
}

type clientSpoolBody bool

func (s clientSpoolBody) apply(opts *clientOptions) {
	opts.spoolBody = bool(s)
}

// WithClientSpoolBody is WithClientBufferBody with each body written to a
// temporary file rather than held in memory, for responses that run to hundreds
// of megabytes, such as a whole feed. The response is handed on with the file
// as its body, and closing the body removes the file. With both options set,
// bodies go to files.
func WithClientSpoolBody(spool bool) ClientOption {
	return clientSpoolBody(spool)
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

	httpClient := options.httpClient
	if options.bufferBody || options.spoolBody {
		// A copy, so that a client the caller passed in is left as it was.
		c := *options.httpClient
		c.Transport = bufferBodyTransport{next: c.Transport, spool: options.spoolBody}
		httpClient = &c
	}

	return &Client{
		HTTPClient:   httpClient,
		Logger:       options.logger,
		RetryWaitMin: options.retryWaitMin,
		RetryWaitMax: options.retryWaitMax,
		RetryMax:     options.retryMax,
		CheckRetry:   options.checkRetry,
		Backoff:      options.backoff,
	}
}

// bufferBodyTransport reads each response body whole within the round trip, so
// that an error in reading it is an error of the round trip, which the client
// retries. It holds the body in memory, or with spool in a temporary file.
type bufferBodyTransport struct {
	next  http.RoundTripper
	spool bool
}

func (t bufferBodyTransport) transport() http.RoundTripper {
	if t.next == nil {
		return http.DefaultTransport
	}
	return t.next
}

func (t bufferBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport().RoundTrip(req)
	if err != nil {
		// As it is: the retry policy tells some errors apart by their type,
		// such as a certificate that does not verify, which is not retried.
		return nil, err
	}
	defer resp.Body.Close()

	if t.spool {
		body, err := spoolBody(resp.Body)
		if err != nil {
			return nil, errors.Wrap(err, "spool response body")
		}
		resp.Body = body
		return resp, nil
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read response body")
	}
	resp.Body = io.NopCloser(bytes.NewReader(bs))

	return resp, nil
}

// spoolBody writes r whole to a temporary file, and returns the file, to be
// read from its start, as a body that removes the file when it is closed. A
// file it could not fill is removed at once.
func spoolBody(r io.Reader) (io.ReadCloser, error) {
	f, err := os.CreateTemp("", "vuls-data-update-body-*")
	if err != nil {
		return nil, errors.Wrap(err, "create temp file")
	}
	body := &tempFileBody{File: f}

	if _, err := io.Copy(f, r); err != nil {
		return nil, stderrors.Join(errors.Wrap(err, "read response body"), body.Close())
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, stderrors.Join(errors.Wrapf(err, "seek %s", f.Name()), body.Close())
	}

	return body, nil
}

// tempFileBody is a body read from a temporary file, which Close removes.
type tempFileBody struct {
	*os.File

	once sync.Once
	err  error
}

func (b *tempFileBody) Close() error {
	b.once.Do(func() {
		b.err = stderrors.Join(b.File.Close(), os.Remove(b.File.Name()))
	})
	return b.err
}

// CloseIdleConnections passes the call on, as http.Client only makes it on a
// transport that has the method. The client makes it when it gives up.
func (t bufferBodyTransport) CloseIdleConnections() {
	if c, ok := t.transport().(interface{ CloseIdleConnections() }); ok {
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
