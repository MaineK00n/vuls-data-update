package list_test

import (
	"bytes"
	"cmp"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/list"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/",
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
					f, err := os.Open(filepath.Join(tt.testdata, fmt.Sprintf("page%s.json", p)))
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
					http.ServeFile(w, r, filepath.Join(tt.testdata, fmt.Sprintf("page%s.json", p)))
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
			default:
				if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}

					if d.IsDir() {
						return nil
					}

					dir, file := filepath.Split(strings.TrimPrefix(path, dir))
					want, err := os.ReadFile(filepath.Join("testdata", "golden", dir, file))
					if err != nil {
						return err
					}

					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					if diff := gocmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}

					return nil
				}); err != nil {
					t.Error("walk error:", err)
				}
			}
		})
	}
}
