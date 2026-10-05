package list_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/enisa/euvd/list"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	type args struct {
		opts []list.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				opts: []list.Option{list.WithConcurrency(1)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "search":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("%s_%s.json", r.URL.Query().Get("page"), r.URL.Query().Get("size"))))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "api", "search")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			opts := append([]list.Option{list.WithBaseURL(u), list.WithDir(dir)}, tt.args.opts...)
			err = list.Fetch(opts...)
			switch {
			case err != nil && !tt.wantErr:
				t.Error("unexpected error:", err)
			case err == nil && tt.wantErr:
				t.Error("expected error has not occurred")
			case err != nil && tt.wantErr:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}

// The goroutines page through the list in parallel, each taking every
// concurrency-th page. Every page has to be requested exactly once: one
// requested twice is another one never requested, and its items never written.
func TestFetch_concurrent(t *testing.T) {
	const pages = 2000

	var mu sync.Mutex
	requested := make(map[int]int)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path.Base(r.URL.Path) {
		case "search":
			p, err := strconv.Atoi(r.URL.Query().Get("page"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			mu.Lock()
			requested[p]++
			mu.Unlock()

			if p >= pages {
				_, _ = fmt.Fprintf(w, `{"items":[],"total":%d}`, pages)
				return
			}
			_, _ = fmt.Fprintf(w, `{"items":[{"id":"EUVD-2025-%d"}],"total":%d}`, 100000+p, pages)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	u, err := url.JoinPath(ts.URL, "api", "search")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	dir := t.TempDir()
	if err := list.Fetch(list.WithBaseURL(u), list.WithDir(dir), list.WithConcurrency(5), list.WithWait(0)); err != nil {
		t.Fatal("unexpected error:", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for p := range pages {
		if requested[p] != 1 {
			t.Errorf("page %d: requested %d times, want 1", p, requested[p])
		}
		if _, err := os.Stat(filepath.Join(dir, "2025", fmt.Sprintf("EUVD-2025-%d.json", 100000+p))); err != nil {
			t.Errorf("page %d: item not written: %v", p, err)
		}
	}
}
