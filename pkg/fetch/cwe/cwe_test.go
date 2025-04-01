package cwe_test

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cwe"
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
			defer ts.Close() //nolint:errcheck

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
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				wantb, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
				if err != nil {
					return err
				}
				gotb, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				switch dir {
				case "weakness":
					var want cwe.Weakness
					if err := json.Unmarshal(wantb, &want); err != nil {
						return err
					}

					var got cwe.Weakness
					if err := json.Unmarshal(gotb, &got); err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}
				case "category":
					var want cwe.Category
					if err := json.Unmarshal(wantb, &want); err != nil {
						return err
					}

					var got cwe.Category
					if err := json.Unmarshal(gotb, &got); err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}
				case "view":
					var want cwe.View
					if err := json.Unmarshal(wantb, &want); err != nil {
						return err
					}

					var got cwe.View
					if err := json.Unmarshal(gotb, &got); err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
