package nistnvd_test

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	nistnvd "github.com/MaineK00n/vuls-data-update/pkg/fetch/vulncheck/nist-nvd"
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
				apiToken: "vulncheck_token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "backup/nist-nvd"):
					if s := r.Header.Get("Authorization"); s != "Bearer vulncheck_token" {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
					}

					bs, err := json.Marshal(struct {
						Benchmark float64 `json:"_benchmark"`
						Meta      struct {
							Timestamp time.Time `json:"timestamp"`
							Index     string    `json:"index"`
						} `json:"_meta"`
						Data []struct {
							Filename      string    `json:"filename"`
							Sha256        string    `json:"sha256"`
							DateAdded     time.Time `json:"date_added"`
							URL           string    `json:"url"`
							URLTTLMinutes int       `json:"url_ttl_minutes"`
							URLExpires    time.Time `json:"url_expires"`
						} `json:"data"`
					}{
						Benchmark: 0.035335,
						Meta: struct {
							Timestamp time.Time `json:"timestamp"`
							Index     string    `json:"index"`
						}{
							Timestamp: time.Now(),
							Index:     "nist-nvd",
						},
						Data: []struct {
							Filename      string    `json:"filename"`
							Sha256        string    `json:"sha256"`
							DateAdded     time.Time `json:"date_added"`
							URL           string    `json:"url"`
							URLTTLMinutes int       `json:"url_ttl_minutes"`
							URLExpires    time.Time `json:"url_expires"`
						}{
							{
								Filename:      "nist-nvd-1754583421218404458.zip",
								Sha256:        "04f071a6ef1b39b9a115425b1b5a3add18571768310cae12f578d4b177bf4de8",
								DateAdded:     time.Now(),
								URL:           fmt.Sprintf("http://%s/nist-nvd-1754583421218404458.zip", r.Host),
								URLTTLMinutes: 15,
								URLExpires:    time.Now(),
							},
						},
					})
					if err != nil {
						http.Error(w, fmt.Sprintf("Internal Server Error. err: %s", err), http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, "", time.Now(), bytes.NewReader(bs))
				default:
					http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, path.Base(r.URL.Path)))
				}
			}))
			defer ts.Close()

			u, err := url.JoinPath(ts.URL, "v3/backup/nist-nvd")
			if err != nil {
				t.Error("unexpected error:", err)
			}

			dir := t.TempDir()
			err = nistnvd.Fetch(tt.args.apiToken, nistnvd.WithBaseURL(u), nistnvd.WithDir(dir), nistnvd.WithRetry(0))
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
