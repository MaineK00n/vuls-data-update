package api_test

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/nuclei/api"
)

type response struct {
	Message string       `json:"message"`
	Count   int          `json:"count"`
	Total   int          `json:"total"`
	Results []api.Result `json:"results"`
}

func TestFetch(t *testing.T) {
	type args struct {
		apikey string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				apikey: "key12345",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/template/public":
					switch r.Method {
					case http.MethodGet:
						if r.Header.Get("X-API-Key") != "key12345" {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}

						offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
						if err != nil {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}

						limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
						if err != nil {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}

						f, err := os.Open(filepath.Join("testdata", "fixtures", tt.name, "public.json"))
						if err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}

						var rs []api.Result
						if err := json.NewDecoder(f).Decode(&rs); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}

						w.WriteHeader(http.StatusOK)
						start := min(offset, len(rs))
						end := min(offset+limit, len(rs))
						if err := json.NewEncoder(w).Encode(response{
							Message: "successfully retrieved public templates",
							Count:   end - start,
							Total: func() int {
								if start >= len(rs) {
									return 0
								}
								return len(rs)
							}(),
							Results: rs[start:end],
						}); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						}
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				case "/v1/template/early":
					switch r.Method {
					case http.MethodGet:
						if r.Header.Get("X-API-Key") != "key12345" {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}

						offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
						if err != nil {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}

						limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
						if err != nil {
							http.Error(w, "Bad Request", http.StatusBadRequest)
							return
						}

						f, err := os.Open(filepath.Join("testdata", "fixtures", tt.name, "early.json"))
						if err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}

						var rs []api.Result
						if err := json.NewDecoder(f).Decode(&rs); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}

						w.WriteHeader(http.StatusOK)
						start := min(offset, len(rs))
						end := min(offset+limit, len(rs))
						if err := json.NewEncoder(w).Encode(response{
							Message: "successfully retrieved early templates",
							Count:   end - start,
							Total: func() int {
								if start >= len(rs) {
									return 0
								}
								return len(rs)
							}(),
							Results: rs[start:end],
						}); err != nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
						}
					default:
						http.Error(w, "Bad Request", http.StatusBadRequest)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "v1/template/")
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			dir := t.TempDir()
			err = api.Fetch(tt.args.apikey, api.WithBaseURL(u), api.WithDir(dir), api.WithRetry(0))
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

					rpath, err := filepath.Rel(dir, path)
					if err != nil {
						return err
					}

					want, err := os.ReadFile(filepath.Join("testdata", "golden", rpath))
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
			}
		})
	}
}
