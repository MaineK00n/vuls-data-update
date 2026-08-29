package appstreamlifecycle_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	appstreamlifecycle "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/appstream-lifecycle"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy",
			testdata: "testdata/fixtures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/support/policy/updates/rhel-app-streams-life-cycle":
					http.ServeFile(w, r, filepath.Join(tt.testdata, "rhel-app-streams-life-cycle.html"))
				case "/support/policy/updates/rhel-app-retired-rolling-streams":
					http.ServeFile(w, r, filepath.Join(tt.testdata, "rhel-retired-rolling-app-stream.html"))
				default:
					http.NotFound(w, r)
				}
			}))
			dir := t.TempDir()
			err := appstreamlifecycle.Fetch(appstreamlifecycle.WithHTTPClient(ts.Client()), appstreamlifecycle.WithDir(dir), appstreamlifecycle.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err != nil:
			case tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
