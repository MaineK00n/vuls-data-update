package epss_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/epss"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		hasError bool
	}{
		{
			name: "happy path",
			args: []string{"2021-04-14", "2021-04-22", "2021-09-01", "2022-02-04", "2023-03-07"},
		},
		{
			name:     "404 not found",
			args:     []string{"2021-04-03"},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", strings.TrimPrefix(r.URL.Path, "/")))
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := epss.Fetch(tt.args, epss.WithDataURL(fmt.Sprintf("%s/epss_scores-%%s.csv.gz", ts.URL)), epss.WithDir(dir), epss.WithRetry(0), epss.WithConcurrency(1), epss.WithWait(0))
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
