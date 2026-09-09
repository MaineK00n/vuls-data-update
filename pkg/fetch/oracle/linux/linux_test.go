package linux_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/oracle/linux"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/com.oracle.elsa-all.xml.bz2",
		},
		{
			name:     "not bzip2 file",
			testdata: "testdata/fixtures/invalid.xml",
			hasError: true,
		},
		{
			name:     "invalid xml",
			testdata: "testdata/fixtures/invalid.xml.bz2",
			hasError: true,
		},
		{
			name:     "404 not found",
			testdata: "",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.testdata == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.testdata)
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := linux.Fetch(linux.WithAdvisoryURL(ts.URL), linux.WithDir(dir), linux.WithRetry(0))
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
