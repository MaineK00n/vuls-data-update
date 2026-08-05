package servicing_test

import (
	"encoding/json"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/servicing"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		kbs      []string
		golden   string
		hasError bool
	}{
		{
			// Both KBs belong to one series, so the listing is read once however
			// many members were asked for.
			name:   "series is listed once",
			kbs:    []string{"KB5033920", "KB5101004"},
			golden: "series-fetched-once",
		},
		{
			// KB5033920 is expired: the catalog no longer serves it and nothing
			// points at it but the listing. Asking for the surviving member has
			// to bring its article along, or the record goes when the listing
			// does.
			name:   "expired member is stored too",
			kbs:    []string{"KB5101004"},
			golden: "expired-member",
		},
		{
			// OS listings carry build numbers and mark previews in the title, and
			// are broken up by version headings that are not articles.
			name:   "os series carries builds",
			kbs:    []string{"KB5101649"},
			golden: "os-series",
		},
		{
			// os/windows collects unrelated one-off articles rather than a
			// series, so neither speaks for the other and there is no listing to
			// follow. Both are recorded from their own headings, including the
			// one that names no KB anywhere.
			name:   "sidebar-less path keeps every article",
			kbs:    []string{"KB890175", "KB4519108"},
			golden: "sidebar-less",
		},
		{
			// Microsoft lists an article it does not serve. Losing the run over
			// one of those would throw away the thousands already fetched, since
			// the tree is wiped at the start.
			name:   "listed article is not served",
			kbs:    []string{"KB5102203"},
			golden: "not-served",
		},
		{
			// A listing can leave its own series: os/server-2008 links to
			// os/windows-8-1/2024/01/end-of-support. That article is stored, but
			// its listing is not read, so the 8.1 series it names does not come
			// along with it.
			name:   "listing leaving the series is followed one hop",
			kbs:    []string{"KB4457984"},
			golden: "cross-series",
		},
		{
			// Pre-2018 articles stay on /help/<KB>. There is no series to read,
			// and that is not a failure.
			name:   "non-servicing article is skipped",
			kbs:    []string{"KB923414"},
			golden: "non-servicing",
		},
		{
			name:     "no KB",
			kbs:      nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(handler(t))
			defer ts.Close()

			dir := t.TempDir()
			err := servicing.Fetch(tt.kbs,
				servicing.WithHelpURL(ts.URL+"/help/%s"),
				servicing.WithDir(dir),
				servicing.WithRetry(0),
				servicing.WithConcurrency(2),
				servicing.WithWait(0),
			)
			switch {
			case err != nil && !tt.hasError:
				t.Fatalf("unexpected error. err: %v", err)
			case err == nil && tt.hasError:
				t.Fatal("expected error has not occurred")
			case err != nil:
				return
			}

			diff(t, filepath.Join("testdata", "golden", tt.golden), dir)
		})
	}
}

// TestFetchRetriesThrottle covers the 403 support.microsoft.com answers with
// when it decides a client is asking too often. The default retry policy stops
// at 429 and 5xx, so without 403 among them the first throttle would end a
// crawl that is thousands of requests long.
func TestFetchRetriesThrottle(t *testing.T) {
	for _, tt := range []struct {
		name     string
		retry    int
		golden   string
		hasError bool
	}{
		// The tree has to come out whole: a throttle that is retried away must
		// leave no trace, and asserting only that Fetch returned nil would pass
		// even if nothing had been stored.
		{name: "throttled once, retried", retry: 2, golden: "os-series"},
		// Throttling that outlasts the retries fails the run rather than
		// committing a tree with articles silently missing from it.
		{name: "throttled once, no retries left", retry: 0, hasError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			throttled := map[string]bool{}

			inner := handler(t)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				first := !throttled[r.URL.Path]
				throttled[r.URL.Path] = true
				mu.Unlock()

				if first && strings.Contains(r.URL.Path, "/servicing/") {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				inner(w, r)
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := servicing.Fetch([]string{"KB5101649"},
				servicing.WithHelpURL(ts.URL+"/help/%s"),
				servicing.WithDir(dir),
				servicing.WithRetry(tt.retry),
				servicing.WithConcurrency(1),
				servicing.WithWait(0),
			)
			switch {
			case err != nil && !tt.hasError:
				t.Fatalf("unexpected error. err: %v", err)
			case err == nil && tt.hasError:
				t.Fatal("expected error has not occurred")
			case err != nil:
				return
			}

			diff(t, filepath.Join("testdata", "golden", tt.golden), dir)
		})
	}
}

// handler serves the fixture tree the way support.microsoft.com serves the real
// one: /help/<KB> redirects to a canonical article path, and everything else is
// an article.
func handler(t *testing.T) http.HandlerFunc {
	t.Helper()

	bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", "happy", "redirects.json"))
	if err != nil {
		t.Fatalf("read redirects. err: %v", err)
	}
	var redirects map[string]string
	if err := json.Unmarshal(bs, &redirects); err != nil {
		t.Fatalf("unmarshal redirects. err: %v", err)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if kb, ok := strings.CutPrefix(r.URL.Path, "/help/"); ok {
			to, ok := redirects[kb]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if to == r.URL.Path {
				// Stays on /help/, as Microsoft does for older articles.
				_, _ = w.Write([]byte("<html><body></body></html>"))
				return
			}
			http.Redirect(w, r, to, http.StatusFound)
			return
		}

		// support.microsoft.com serves the same article under DotNetFramework
		// and dotnetframework; the fixtures are stored once, so the lookup has
		// to fold case the way the site does.
		bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", "happy", strings.ToLower(filepath.Clean(r.URL.Path))+".html"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(bs)
	}
}

// diff compares the produced tree against golden byte for byte. Bytes rather
// than parsed content: origin/ is only worth keeping if
// it reproduces exactly, and raw/ is written deterministically, so any
// difference at all is a regression.
func diff(t *testing.T, golden, got string) {
	t.Helper()

	want := walk(t, golden)
	have := walk(t, got)

	if d := cmp.Diff(slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(have))); d != "" {
		t.Errorf("files (-expected +got):\n%s", d)
	}

	for n, w := range want {
		h, ok := have[n]
		if !ok {
			continue
		}
		if d := cmp.Diff(string(w), string(h)); d != "" {
			t.Errorf("%s (-expected +got):\n%s", n, d)
		}
	}
}

func walk(t *testing.T, root string) map[string][]byte {
	t.Helper()

	out := make(map[string][]byte)
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}

		bs, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		out[filepath.ToSlash(rel)] = bs
		return nil
	}); err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s. err: %v", root, err)
	}

	return out
}
