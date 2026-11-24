package http_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

// countingTransport answers every request with 200 and counts them.
type countingTransport struct {
	n int
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.n++
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func TestNewClient_WithClientHTTPClient(t *testing.T) {
	tests := []struct {
		name     string
		supplied bool
	}{
		{
			// production fetchers forward their test-only httpClient field,
			// which is nil outside tests, so the pooled default has to stay
			name: "nil keeps the default",
		},
		{
			name:     "supplied client is used",
			supplied: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				client    *http.Client
				transport countingTransport
			)
			if tt.supplied {
				client = &http.Client{Transport: &transport}
			}

			c := utilhttp.NewClient(utilhttp.WithClientHTTPClient(client))
			if c.HTTPClient == nil {
				t.Fatal("HTTPClient is nil, want a client")
			}
			if !tt.supplied {
				return
			}

			// The client holds a copy of what it is given, so what shows the
			// supplied client is used is a request reaching its transport.
			resp, err := c.Get("https://example.com/")
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			defer resp.Body.Close()
			if transport.n != 1 {
				t.Errorf("requests through the supplied transport = %d, want 1", transport.n)
			}
		})
	}
}

func TestNewClient_PlainHTTP(t *testing.T) {
	tests := []struct {
		name string
		url  string
		opts []utilhttp.ClientOption
		// reqs is how many requests reach the server.
		reqs     int64
		hasError bool
	}{
		{
			name: "https",
			url:  "https://example.com/",
			reqs: 1,
		},
		{
			name:     "plain http",
			url:      "http://example.com/",
			hasError: true,
		},
		{
			name: "plain http, allowed",
			url:  "http://example.com/",
			opts: []utilhttp.ClientOption{utilhttp.WithClientAllowPlainHTTP(true)},
			reqs: 1,
		},
		{
			// The https request reaches the server, which redirects it to
			// plain http.
			name:     "redirect to plain http",
			url:      "https://example.com/redirect",
			reqs:     1,
			hasError: true,
		},
		{
			name: "redirect to plain http, allowed",
			url:  "https://example.com/redirect",
			opts: []utilhttp.ClientOption{utilhttp.WithClientAllowPlainHTTP(true)},
			reqs: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqs atomic.Int64
			// The in-memory network sends http and https requests alike to
			// the test server, whatever their host.
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reqs.Add(1)
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "http://example.com/", http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))

			c := utilhttp.NewClient(append([]utilhttp.ClientOption{utilhttp.WithClientHTTPClient(ts.Client()), utilhttp.WithClientRetryMax(3), utilhttp.WithClientRetryWaitMin(time.Millisecond), utilhttp.WithClientRetryWaitMax(time.Millisecond)}, tt.opts...)...)
			resp, err := c.Get(tt.url)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				resp.Body.Close()
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				if !errors.Is(err, utilhttp.ErrPlainHTTP) {
					t.Errorf("error = %v, want a refused plain http request", err)
				}
				// Every retry would be refused again, so there is none.
				if !strings.Contains(err.Error(), "giving up after 1 attempt(s)") {
					t.Errorf("error = %v, want it given up after the first attempt", err)
				}
			default:
				resp.Body.Close()
			}
			if got := reqs.Load(); got != tt.reqs {
				t.Errorf("requests reaching the server = %d, want %d", got, tt.reqs)
			}
		})
	}
}

func TestClient_PipelineGet(t *testing.T) {
	tests := []struct {
		name        string
		urls        int
		concurrency int
		hasError    bool
	}{
		{
			name:        "happy",
			urls:        3,
			concurrency: 1,
		},
		{
			// errgroup would block on the first request rather than
			// return, so this has to be rejected up front
			name:        "zero concurrency",
			urls:        1,
			concurrency: 0,
			hasError:    true,
		},
		{
			name:        "zero concurrency, nothing to fetch",
			urls:        0,
			concurrency: 0,
			hasError:    true,
		},
		{
			// errgroup reads a negative limit as no limit at all, which
			// is a shape callers may rely on and not what is broken here
			name:        "negative concurrency",
			urls:        3,
			concurrency: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The in-memory network sends every request to the test server,
			// whatever its host.
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			urls := make([]string, 0, tt.urls)
			for range tt.urls {
				urls = append(urls, "https://example.com/")
			}

			done := make(chan error, 1)
			go func() {
				done <- utilhttp.NewClient(utilhttp.WithClientHTTPClient(ts.Client())).PipelineGet(urls, tt.concurrency, 0, true, func(resp *http.Response) error {
					defer resp.Body.Close()
					return nil
				})
			}()

			select {
			case err := <-done:
				switch {
				case err != nil && !tt.hasError:
					t.Error("unexpected error:", err)
				case err == nil && tt.hasError:
					t.Error("expected error has not occurred")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("PipelineGet() did not return")
			}
		})
	}
}
