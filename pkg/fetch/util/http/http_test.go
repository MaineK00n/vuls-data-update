package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"

	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

func TestNewClient_WithClientHTTPClient(t *testing.T) {
	supplied := &http.Client{}

	tests := []struct {
		name   string
		client *http.Client
	}{
		{
			// production fetchers forward their test-only httpClient field,
			// which is nil outside tests, so the pooled default has to stay
			name:   "nil keeps the default",
			client: nil,
		},
		{
			name:   "supplied client is used",
			client: supplied,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := utilhttp.NewClient(utilhttp.WithClientHTTPClient(tt.client)).HTTPClient
			switch {
			case tt.client == nil && got == nil:
				t.Error("HTTPClient is nil, want the pooled default")
			case tt.client != nil && got != tt.client:
				t.Errorf("HTTPClient = %p, want the supplied client %p", got, tt.client)
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

func TestClient_PipelineGet_error(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		status  int
		wantErr string
	}{
		{
			// The URL is what a failed request is traced by. Nothing of the
			// response is part of the message: not its headers, which carry
			// a cookie here, and not its pointers.
			name:    "continuation",
			url:     "https://example.com/2026/advisory.json",
			status:  http.StatusNotFound,
			wantErr: "err in goroutine: continuation, url: https://example.com/2026/advisory.json: error response with status code 404",
		},
		{
			name:    "continuation, password in the URL",
			url:     "https://user:password@example.com/2026/advisory.json",
			status:  http.StatusNotFound,
			wantErr: "err in goroutine: continuation, url: https://user:xxxxx@example.com/2026/advisory.json: error response with status code 404",
		},
		{
			// The request itself failed, so the continuation is never called,
			// and it is Do that names the URL.
			name:    "do, password in the URL",
			url:     "https://user:password@example.com/2026/advisory.json",
			status:  http.StatusInternalServerError,
			wantErr: "err in goroutine: do: http request, url: https://user:xxxxx@example.com/2026/advisory.json: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret"})
				w.WriteHeader(tt.status)
			}))

			err := utilhttp.NewClient(utilhttp.WithClientHTTPClient(ts.Client()), utilhttp.WithClientRetryMax(0)).PipelineGet([]string{tt.url}, 1, 0, true, func(resp *http.Response) error {
				defer resp.Body.Close()
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			})
			if err == nil || !strings.HasPrefix(err.Error(), tt.wantErr) {
				t.Errorf("PipelineGet() error = %v, want it to start with %q", err, tt.wantErr)
			}
		})
	}
}
