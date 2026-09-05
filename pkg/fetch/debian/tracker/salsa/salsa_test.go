package salsa_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
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
			testdata: "testdata/fixtures/security-tracker-master.tar.gz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, tt.testdata)
			if err != nil {
				t.Error("unexpected error:", err)
			}

			var m salsa.Mirror
			m.ReleaseStable, err = url.JoinPath(ts.URL, "testdata", "fixtures", "release", "debian")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ReleaseSecurity, err = url.JoinPath(ts.URL, "testdata", "fixtures", "release", "debian-security")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ReleaseBackport, err = url.JoinPath(ts.URL, "testdata", "fixtures", "release", "debian")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ArchiveStable, err = url.JoinPath(ts.URL, "testdata", "fixtures", "archive", "debian")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ArchiveSecurity, err = url.JoinPath(ts.URL, "testdata", "fixtures", "archive", "debian-security")
			if err != nil {
				t.Error("unexpected error:", err)
			}
			m.ArchiveBackport, err = url.JoinPath(ts.URL, "testdata", "fixtures", "archive", "debian-backports")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = salsa.Fetch(salsa.WithDataURL(u), salsa.WithDir(dir), salsa.WithRetry(0), salsa.WithMirror(m))
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
