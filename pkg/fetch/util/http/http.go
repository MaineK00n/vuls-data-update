package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

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

func Get(url string, retry int, opts ...RequestOption) ([]byte, error) {
	return Do(http.MethodGet, url, retry, opts...)
}

func MultiGet(urls []string, concurrency, wait, retry int, opts ...RequestOption) ([][]byte, error) {
	g, ctx := errgroup.WithContext(context.Background())
	urlChan := make(chan string)
	go func() {
		defer close(urlChan)
		for _, u := range urls {
			urlChan <- u
		}
	}()

	respChan := make(chan []byte, len(urls))
	bar := pb.Full.Start(len(urls))
	for i := 0; i < concurrency; i++ {
		g.Go(func() error {
			for u := range urlChan {
				bs, err := Get(u, retry, opts...)
				if err != nil {
					return err
				}
				select {
				case respChan <- bs:
					bar.Increment()
				case <-ctx.Done():
					return ctx.Err()
				}
				time.Sleep(time.Duration(wait) * time.Second)
			}
			return nil
		})
	}
	go func() {
		_ = g.Wait()
		bar.Finish()
		close(respChan)
	}()

	bss := make([][]byte, 0, len(urls))
	for r := range respChan {
		bss = append(bss, r)
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return bss, nil
}

func POST(url string, retry int, opts ...RequestOption) ([]byte, error) {
	return Do(http.MethodPost, url, retry, opts...)
}

func Do(method, url string, retry int, opts ...RequestOption) ([]byte, error) {
	options := &requestOptions{
		header: nil,
		body:   nil,
	}

	for _, o := range opts {
		o.apply(options)
	}

	rc := retryablehttp.NewClient()
	rc.RetryMax = retry
	rc.Logger = nil

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

	resp, err := rc.Do(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "http request, url: %s", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("Error request response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read response body")
	}

	return bs, nil
}
