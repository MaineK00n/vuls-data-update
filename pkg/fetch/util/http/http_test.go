package http_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
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
			wantErr: "1 of 1 requests failed: continuation, url: https://example.com/2026/advisory.json: error response with status code 404",
		},
		{
			name:    "continuation, password in the URL",
			url:     "https://user:password@example.com/2026/advisory.json",
			status:  http.StatusNotFound,
			wantErr: "1 of 1 requests failed: continuation, url: https://user:xxxxx@example.com/2026/advisory.json: error response with status code 404",
		},
		{
			// The request itself failed, so the continuation is never called,
			// and it is Do that names the URL.
			name:    "do, password in the URL",
			url:     "https://user:password@example.com/2026/advisory.json",
			status:  http.StatusInternalServerError,
			wantErr: "1 of 1 requests failed: do: http request, url: https://user:xxxxx@example.com/2026/advisory.json: ",
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
			// Neither the password nor the cookie reaches any part of the message.
			for _, s := range []string{"password", "secret"} {
				if err != nil && strings.Contains(err.Error(), s) {
					t.Errorf("PipelineGet() error = %v, want it not to contain %q", err, s)
				}
			}
		})
	}
}

func TestClient_PipelineGet_errors(t *testing.T) {
	urls := func(n int) []string {
		us := make([]string, 0, n)
		for i := range n {
			us = append(us, fmt.Sprintf("https://example.com/%d.json", i))
		}
		return us
	}

	tests := []struct {
		name        string
		urls        []string
		fail        []string
		concurrency int
		wantPrefix  string
		wantNamed   int
	}{
		{
			// A failed request does not stop the others, so the error names
			// every one that failed, and none that did not. One at a time,
			// the request after the first failure is made only if a failure
			// stops nothing.
			name:        "every failure is named",
			urls:        urls(3),
			fail:        []string{"https://example.com/0.json", "https://example.com/2.json"},
			concurrency: 1,
			wantPrefix:  "2 of 3 requests failed: ",
			wantNamed:   2,
		},
		{
			// A source that is down fails every request the same way, so
			// past the limit the rest are only counted.
			name:        "past the limit, the rest are only counted",
			urls:        urls(25),
			fail:        urls(25),
			concurrency: 4,
			wantPrefix:  "25 of 25 requests failed (first 20 shown): ",
			wantNamed:   20,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if slices.Contains(tt.fail, fmt.Sprintf("https://example.com%s", r.URL.Path)) {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))

			err := utilhttp.NewClient(utilhttp.WithClientHTTPClient(ts.Client()), utilhttp.WithClientRetryMax(0)).PipelineGet(tt.urls, tt.concurrency, 0, true, func(resp *http.Response) error {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return errors.Errorf("error response with status code %d", resp.StatusCode)
				}
				return nil
			})
			if err == nil || !strings.HasPrefix(err.Error(), tt.wantPrefix) {
				t.Fatalf("PipelineGet() error = %v, want it to start with %q", err, tt.wantPrefix)
			}
			if got := strings.Count(err.Error(), "continuation, url: "); got != tt.wantNamed {
				t.Errorf("PipelineGet() error names %d requests, want %d:\n%v", got, tt.wantNamed, err)
			}
			for _, u := range tt.urls {
				if !slices.Contains(tt.fail, u) && strings.Contains(err.Error(), fmt.Sprintf("url: %s:", u)) {
					t.Errorf("PipelineGet() error names %s, which did not fail:\n%v", u, err)
				}
			}
		})
	}
}
