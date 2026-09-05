package cwe_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/cwe"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		hasError bool
	}{
		{
			name: "happy path",
			file: "testdata/fixtures/cwec_latest.xml.zip",
		},
		{
			name:     "404 not found",
			file:     "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.file == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.file)
			}))
			defer ts.Close()

			dataURL, err := url.JoinPath(ts.URL, tt.file)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			dir := t.TempDir()
			err = cwe.Fetch(cwe.WithDataURL(dataURL), cwe.WithDir(dir), cwe.WithRetry(0))
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
