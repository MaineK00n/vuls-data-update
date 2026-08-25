package cvrf_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/cvrf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	type args struct {
		// baseURL is the endpoint root; the fixtures under it mirror the real
		// API layout (<baseURL>/updates and <baseURL>/cvrf/<YYYY-Mon>).
		baseURL          string
		supplementMonths int
	}
	tests := []struct {
		name string
		args args
		// referenceTime pins the package clock via SetTimeNowFunc; it is test
		// harness setup, not a Fetch argument. Zero leaves the real clock.
		referenceTime time.Time
		golden        string
		hasError      bool
	}{
		{
			name: "happy path",
			args: args{
				baseURL:          "testdata/fixtures/happy",
				supplementMonths: 0,
			},
			golden: "testdata/golden/happy",
		},
		{
			// The index lists only 2016-Apr; 2024-Mar is dropped from the index
			// but still resolves at its direct document URL. With the clock
			// anchored to 2024-Apr, supplement recovers 2024-Mar (and 404-skips
			// the not-yet-published 2024-Apr).
			name: "supplement recovers month dropped from index",
			args: args{
				baseURL:          "testdata/fixtures/supplement",
				supplementMonths: 2,
			},
			referenceTime: time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC),
			golden:        "testdata/golden/supplement",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.referenceTime.IsZero() {
				defer cvrf.SetTimeNowFunc(func() time.Time { return tt.referenceTime })()
			}

			// The fixtures mirror the real API layout, so no response rewriting
			// is needed: <baseURL>/updates and <baseURL>/cvrf/<YYYY-Mon> are
			// served straight off disk, and an absent month yields a 404.
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rel, ok := strings.CutPrefix(r.URL.Path, "/cvrf/v3.0/")
				if !ok {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join(tt.args.baseURL, rel))
			}))
			dir := t.TempDir()
			err := cvrf.Fetch(cvrf.WithHTTPClient(ts.Client()), cvrf.WithDir(dir), cvrf.WithRetry(0), cvrf.WithSupplementMonths(tt.args.supplementMonths))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				utiltest.Diff(t, tt.golden, dir)
			}
		})
	}
}
