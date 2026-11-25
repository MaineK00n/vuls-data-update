package nistnvd_test

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
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
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			dir := t.TempDir()
			err := nistnvd.Fetch(tt.args.apiToken, nistnvd.WithHTTPClient(ts.Client()), nistnvd.WithDir(dir), nistnvd.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}

func TestCVEItems(t *testing.T) {
	tests := []struct {
		name    string
		feed    string
		want    []string
		wantErr bool
	}{
		{
			name: "members around CVE_Items",
			feed: `{"CVE_data_type":"CVE","CVE_Items":[{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0001","ASSIGNER":"a"}}},{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0002","ASSIGNER":"a"}}}],"CVE_data_timestamp":"2025-08-07T00:00Z"}`,
			want: []string{"CVE-2025-0001", "CVE-2025-0002"},
		},
		{
			name: "empty CVE_Items",
			feed: `{"CVE_data_type":"CVE","CVE_Items":[]}`,
		},
		{
			name: "null CVE_Items",
			feed: `{"CVE_data_type":"CVE","CVE_Items":null}`,
		},
		{
			name: "no CVE_Items",
			feed: `{"CVE_data_type":"CVE"}`,
		},
		{
			name:    "not an object",
			feed:    `[]`,
			wantErr: true,
		},
		{
			name:    "CVE_Items not an array",
			feed:    `{"CVE_Items":{}}`,
			wantErr: true,
		},
		{
			name:    "an item that does not decode",
			feed:    `{"CVE_Items":[{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0001","ASSIGNER":"a"}}},{"cve":1}]}`,
			want:    []string{"CVE-2025-0001"},
			wantErr: true,
		},
		{
			name:    "cut off",
			feed:    `{"CVE_Items":[{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0001","ASSIGNER":"a"}}},`,
			want:    []string{"CVE-2025-0001"},
			wantErr: true,
		},
		{
			name:    "cut off in a member before CVE_Items",
			feed:    `{"CVE_data_type":"CV`,
			wantErr: true,
		},
		{
			name:    "a member before CVE_Items that is not JSON",
			feed:    `{"CVE_data_type":tru,"CVE_Items":[]}`,
			wantErr: true,
		},
		{
			name:    "cut off in a member after CVE_Items",
			feed:    `{"CVE_Items":[{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0001","ASSIGNER":"a"}}}],"CVE_data_timestamp":"2025`,
			want:    []string{"CVE-2025-0001"},
			wantErr: true,
		},
		{
			name:    "CVE_Items twice",
			feed:    `{"CVE_Items":[],"CVE_Items":[]}`,
			wantErr: true,
		},
		{
			name:    "null feed",
			feed:    `null`,
			wantErr: true,
		},
		{
			name:    "data after the feed",
			feed:    `{"CVE_Items":[]} {}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				got []string
				err error
			)
			for v, e := range nistnvd.CVEItems(strings.NewReader(tt.feed)) {
				if e != nil {
					err = e
					break
				}
				got = append(got, v.Cve.CVEDataMeta.ID)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("CVEItems() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}
		})
	}
}

// TestCVEItems_streaming checks that an item is yielded as soon as it is read,
// before the rest of the feed has even been written, which is what keeps a
// feed of gigabytes out of memory.
func TestCVEItems_streaming(t *testing.T) {
	pr, pw := io.Pipe()
	yielded := make(chan struct{})
	go func() {
		if _, err := io.WriteString(pw, `{"CVE_Items":[{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0001","ASSIGNER":"a"}}},`); err != nil {
			pw.CloseWithError(err)
			return
		}
		select {
		case <-yielded:
		case <-time.After(10 * time.Second):
			pw.CloseWithError(errors.New("no item was yielded before the rest of the feed was written"))
			return
		}
		_, err := io.WriteString(pw, `{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0002","ASSIGNER":"a"}}}]}`)
		pw.CloseWithError(err)
	}()

	var got []string
	for v, err := range nistnvd.CVEItems(pr) {
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if len(got) == 0 {
			close(yielded)
		}
		got = append(got, v.Cve.CVEDataMeta.ID)
	}
	if diff := cmp.Diff([]string{"CVE-2025-0001", "CVE-2025-0002"}, got); diff != "" {
		t.Errorf("(-expected +got):\n%s", diff)
	}
}

// TestCVEItems_break checks that a loop may stop before the feed ends.
func TestCVEItems_break(t *testing.T) {
	for v, err := range nistnvd.CVEItems(strings.NewReader(`{"CVE_Items":[{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0001","ASSIGNER":"a"}}},{"cve":{"CVE_data_meta":{"ID":"CVE-2025-0002","ASSIGNER":"a"}}}]}`)) {
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if v.Cve.CVEDataMeta.ID != "CVE-2025-0001" {
			t.Errorf("unexpected first item. expected: %q, actual: %q", "CVE-2025-0001", v.Cve.CVEDataMeta.ID)
		}
		break
	}
}
