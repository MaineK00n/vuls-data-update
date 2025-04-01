package kev_test

import (
	"bytes"
	"encoding/json"
	"fmt"
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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/vulncheck/kev"
)

func TestFetch(t *testing.T) {
	type args struct {
		apiToken string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				apiToken: "token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "vulncheck-kev"):
					c, err := r.Cookie("token")
					if err != nil {
						http.Error(w, fmt.Sprintf("Bad Request. err: %s", err), http.StatusBadRequest)
						return
					}
					if c.Value != tt.args.apiToken {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}

					bs, err := json.Marshal(struct {
						Benchmark float64 `json:"_benchmark"`
						Meta      struct {
							Timestamp string `json:"timestamp"`
							Index     string `json:"index"`
						} `json:"_meta"`
						Data []struct {
							Filename      string `json:"filename"`
							Sha256        string `json:"sha256"`
							DateAdded     string `json:"date_added"`
							URL           string `json:"url"`
							URLTTLMinutes int    `json:"url_ttl_minutes"`
							URLExpires    string `json:"url_expires"`
						} `json:"data"`
					}{
						Benchmark: 0.979224,
						Meta: struct {
							Timestamp string "json:\"timestamp\""
							Index     string "json:\"index\""
						}{
							Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
							Index:     "vulncheck-kev",
						},
						Data: []struct {
							Filename      string "json:\"filename\""
							Sha256        string "json:\"sha256\""
							DateAdded     string "json:\"date_added\""
							URL           string "json:\"url\""
							URLTTLMinutes int    "json:\"url_ttl_minutes\""
							URLExpires    string "json:\"url_expires\""
						}{
							{
								Filename:  "vulncheck-kev-1723803822402071515.zip",
								Sha256:    "91536eafc74ac99bf6da67d17ccddb700aa0b0adc0d932a1569ec8dc57321092",
								DateAdded: "2024-08-16T10:23:42.402Z",
								URL: func() string {
									return fmt.Sprintf("http://%s/testdata/fixtures/vulncheck-kev-1723803822402071515.zip", r.Host)
								}(),
								URLTTLMinutes: 60,
								URLExpires:    "2024-08-16T11:23:42.402Z",
							},
						},
					})
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						return
					}

					http.ServeContent(w, r, "vulncheck-kev.json", time.Now(), bytes.NewReader(bs))
				default:
					http.ServeFile(w, r, strings.TrimPrefix(r.URL.Path, string(os.PathSeparator)))
				}
			}))
			defer ts.Close() //nolint:errcheck

			u, err := url.JoinPath(ts.URL, "vulncheck-kev")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = kev.Fetch(tt.args.apiToken, kev.WithBaseURL(u), kev.WithDir(dir), kev.WithRetry(0))
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
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
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
		})
	}
}
