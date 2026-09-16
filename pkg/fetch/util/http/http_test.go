package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

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
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()

			urls := make([]string, 0, tt.urls)
			for range tt.urls {
				urls = append(urls, ts.URL)
			}

			done := make(chan error, 1)
			go func() {
				done <- utilhttp.NewClient().PipelineGet(urls, tt.concurrency, 0, true, func(resp *http.Response) error {
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
