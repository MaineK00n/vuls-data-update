package v2_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"testing"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name  string
		feeds []string
		// cut has the body of the first response fail partway.
		cut      bool
		hasError bool
	}{
		{
			name:  "happy path",
			feeds: []string{"2002", "2021", "modified"},
		},
		{
			// NVD now and then cuts a feed off partway with an HTTP/2 stream
			// error. The first feed is cut off here, is asked for again, and
			// the fetch comes out as if it had not been.
			name:  "body cut off partway",
			feeds: []string{"2002", "2021", "modified"},
			cut:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", path.Base(r.URL.Path)))
			}))

			hc, retry := ts.Client(), 0
			var cut *utiltest.CutBody
			if tt.cut {
				cut = &utiltest.CutBody{Next: hc.Transport, After: 16, Err: errors.New("stream error: stream ID 1; INTERNAL_ERROR; received from peer")}
				hc, retry = &http.Client{Transport: cut}, 1
			}
			dir := t.TempDir()
			err := v2.Fetch(v2.WithHTTPClient(hc), v2.WithFeeds(tt.feeds), v2.WithDir(dir), v2.WithRetry(retry))
			if cut != nil && !cut.Cut() {
				t.Error("no response was cut off")
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
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
