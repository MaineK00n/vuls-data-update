package cvrf_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/microsoft/cvrf"
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
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			base, err := url.JoinPath(ts.URL, tt.args.baseURL)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = cvrf.Fetch(cvrf.WithBaseURL(base), cvrf.WithDir(dir), cvrf.WithRetry(0), cvrf.WithSupplementMonths(tt.args.supplementMonths))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					dir, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join(tt.golden, dir, file))
					if err != nil {
						return err
					}

					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}

					return nil
				}); err != nil {
					t.Error("walk error:", err)
				}

				// Also walk golden→output so a missing file (e.g. a month that
				// supplement failed to recover) is caught, not just mismatched
				// content of files that happen to exist.
				goldenRoot := tt.golden
				if err := filepath.WalkDir(goldenRoot, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					rel, err := filepath.Rel(goldenRoot, path)
					if err != nil {
						return err
					}
					if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
						t.Errorf("expected output file is missing: %s", rel)
					}

					return nil
				}); err != nil {
					t.Error("walk error:", err)
				}
			}
		})
	}
}
