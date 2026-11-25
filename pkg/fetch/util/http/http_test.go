package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

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

func TestNewClient_WithClientBufferBody(t *testing.T) {
	const body = `{"updates":[{"alias":"FEDORA-2026-c3ea7d7b0e"}]}`

	tests := []struct {
		name   string
		buffer bool
		// cut is how many responses are cut off partway through the body
		// before one is sent whole.
		cut          int
		want         string
		wantRequests int
		hasError     bool
	}{
		{
			// The body is read within the retry loop, so a cut one is asked
			// for again, for as many retries as the client has.
			name:         "buffered",
			buffer:       true,
			cut:          2,
			want:         body,
			wantRequests: 3,
		},
		{
			name:         "buffered, retries run out",
			buffer:       true,
			cut:          3,
			wantRequests: 3,
			hasError:     true,
		},
		{
			// Without it, the response is returned once its header is in, and
			// the cut fails whatever reads the body, with no retry.
			name:         "not buffered",
			cut:          1,
			wantRequests: 1,
			hasError:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int64
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				if requests.Add(1) > int64(tt.cut) {
					_, _ = io.WriteString(w, body)
					return
				}
				// Half of the body, and then the connection is gone.
				_, _ = io.WriteString(w, body[:len(body)/2])
				_ = http.NewResponseController(w).Flush()
				panic(http.ErrAbortHandler)
			}))

			hc := ts.Client()
			transport := hc.Transport
			client := utilhttp.NewClient(utilhttp.WithClientHTTPClient(hc), utilhttp.WithClientRetryMax(2), utilhttp.WithClientRetryWaitMin(time.Millisecond), utilhttp.WithClientRetryWaitMax(time.Millisecond), utilhttp.WithClientBufferBody(tt.buffer))
			if hc.Transport != transport {
				t.Error("NewClient() changed the Transport of the client passed in")
			}

			got, err := func() (string, error) {
				resp, err := client.Get("https://example.com/updates")
				if err != nil {
					return "", err
				}
				defer resp.Body.Close()
				bs, err := io.ReadAll(resp.Body)
				return string(bs), err
			}()
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil && got != tt.want:
				t.Errorf("body = %q, want %q", got, tt.want)
			}
			if n := requests.Load(); n != int64(tt.wantRequests) {
				t.Errorf("requests = %d, want %d", n, tt.wantRequests)
			}
		})
	}
}

// closeIdleCounter is a transport that counts the calls to its
// CloseIdleConnections.
type closeIdleCounter struct {
	http.RoundTripper
	calls int
}

func (c *closeIdleCounter) CloseIdleConnections() {
	c.calls++
}

func TestNewClient_WithClientBufferBody_CloseIdleConnections(t *testing.T) {
	// The client closes idle connections when it gives up on a request, and
	// http.Client passes the call only to a transport that has the method.
	inner := &closeIdleCounter{RoundTripper: http.DefaultTransport}
	client := utilhttp.NewClient(utilhttp.WithClientHTTPClient(&http.Client{Transport: inner}), utilhttp.WithClientBufferBody(true))
	client.HTTPClient.CloseIdleConnections()
	if inner.calls != 1 {
		t.Errorf("CloseIdleConnections calls on the inner transport = %d, want 1", inner.calls)
	}
}
