package list_test

import (
	"bytes"
	"cmp"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/list"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		hasError bool
	}{
		{
			name: "happy",
		},
		{
			name:     "no-advisories",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := r.URL.Query().Get("page")
				if p == "" {
					http.NotFound(w, r)
					return
				}

				switch r.URL.Query().Get("sort") {
				case "doc":
					f, err := os.Open(filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("page%s.json", p)))
					if err != nil {
						http.Error(w, fmt.Sprintf("open testdata: %v", err), http.StatusInternalServerError)
						return
					}
					defer f.Close() //nolint:errcheck

					stat, err := f.Stat()
					if err != nil {
						http.Error(w, fmt.Sprintf("stat testdata: %v", err), http.StatusInternalServerError)
						return
					}

					var data []list.Advisory
					if err := json.UnmarshalRead(f, &data); err != nil {
						http.Error(w, fmt.Sprintf("decode testdata: %v", err), http.StatusInternalServerError)
						return
					}

					slices.SortFunc(data, func(a, b list.Advisory) int {
						return cmp.Compare(a.ID, b.ID)
					})

					bs, err := json.Marshal(data)
					if err != nil {
						http.Error(w, fmt.Sprintf("marshal response: %v", err), http.StatusInternalServerError)
						return
					}

					http.ServeContent(w, r, fmt.Sprintf("page%s.json", p), stat.ModTime(), bytes.NewReader(bs))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, fmt.Sprintf("page%s.json", p)))
				}
			}))
			defer ts.Close()

			dir := t.TempDir()
			err := list.Fetch(list.WithDataURL(fmt.Sprintf("%s/json/?page=%%d&limit=100&sort=doc", ts.URL)), list.WithDir(dir), list.WithRetry(0))
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
