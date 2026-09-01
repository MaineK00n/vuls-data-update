package msuc_test

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/msuc"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		queries  []string
		wantLogs []string
		wantErr  string
		hasError bool
	}{
		{
			name:    "happy",
			queries: []string{"KB5025239"},
			// The catalog would not serve one of the pages the crawl reached,
			// so the walk stopped there. Name it: the log is the only trace a
			// truncated crawl leaves -- and keep it out of the count, which is
			// of records written. Five updates are walked here, four written.
			wantLogs: []string{
				"updateids=00000000-1519-4df8-85c1-d985be7f49c3",
				`msg="Fetched updates" count=4`,
			},
		},
		{
			// The catalog answering "we found nothing" is a normal miss: that
			// seed's update has been expired out of the catalog. The queries
			// that do land still have to come through untouched.
			name:    "partial-no-result",
			queries: []string{"KB5025239", "KB5040427"},
			// Naming the seed that missed is what a seed-list review reads.
			wantLogs: []string{"queries=KB5040427"},
		},
		{
			// Nothing found for any seed, though, is a seed list that has
			// stopped describing anything the catalog holds.
			name:     "no-result",
			queries:  []string{"KB5025239"},
			wantErr:  "all 1 search queries found nothing",
			hasError: true,
		},
		{
			// Not the search page at all: the catalog answers its home page and
			// Thanks.aspx with HTTP 200 as well, and neither can be read the way
			// the search page is.
			name:     "no-container",
			queries:  []string{"KB5025239"},
			wantErr:  "no result container",
			hasError: true,
		},
		{
			// The crawl reached something that is not an update page. Every
			// field is read out of an element, so it would otherwise parse into
			// an update of empty strings and be written out as a good record.
			name:     "bad-update-page",
			queries:  []string{"KB5025239"},
			wantErr:  "no title element",
			hasError: true,
		},
		{
			// Neither result rows nor a no-result message: the catalog never
			// really answered, which is what a throttled search looks like. It
			// has to fail rather than yield an empty result that would be
			// published over the last good one.
			name:     "unanswered",
			queries:  []string{"KB5025239"},
			wantErr:  "neither results nor a no-result message",
			hasError: true,
		},
		{
			// One unanswered search is enough, even where others landed: a
			// throttled run that still finds something would otherwise publish
			// a result short by however much it was not told about.
			name:    "partial-unanswered",
			queries: []string{"KB5025239", "KB0000000"},
			// Which queries went unanswered is what a retry is decided on.
			wantLogs: []string{"queries=KB0000000"},
			wantErr:  "neither results nor a no-result message",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch path.Base(r.URL.Path) {
				case "Search.aspx":
					bs, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "Search.aspx", strings.TrimPrefix(string(bs), "q=")))
				case "ScopedViewInline.aspx":
					switch r.URL.Query().Get("updateid") {
					case "00000000-1519-4df8-85c1-d985be7f49c3":
						http.Redirect(w, r, "/Thanks.aspx?id=190", http.StatusFound)
					default:
						http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "ScopedViewInline.aspx", r.URL.Query().Get("updateid")))
					}
				case "Thanks.aspx":
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, "Thanks.aspx", r.URL.Query().Get("id")))
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			var logs bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			dir := t.TempDir()
			err := msuc.Fetch(tt.queries, msuc.WithMSUCURL(ts.URL), msuc.WithDir(dir), msuc.WithRetry(0))

			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("Fetch() error = %v, want it to contain %q", err, tt.wantErr)
			}

			for _, want := range tt.wantLogs {
				if !strings.Contains(logs.String(), want) {
					t.Errorf("Fetch() log does not contain %q, log:\n%s", want, logs.String())
				}
			}

			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
