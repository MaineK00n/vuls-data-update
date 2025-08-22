package tag_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/remote/tag"
)

func TestTag(t *testing.T) {
	type args struct {
		imageRef string
		newTag   string
		token    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				imageRef: "ghcr.io/test-owner/test-pack:existing-tag",
				newTag:   "new-tag",
				token:    "token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, _, _ := strings.Cut(strings.TrimPrefix(tt.args.imageRef, "ghcr.io/"), ":")
			reg := registry.New()
			s := httptest.NewTLSServer(reg)
			defer s.Close()

			originalTransport := http.DefaultTransport
			http.DefaultTransport = s.Client().Transport
			defer func() {
				http.DefaultTransport = originalTransport
			}()

			for tag, content := range map[string]string{
				"existing-tag": "bar",
				"another-tag":  "foo",
			} {
				u, err := url.Parse(fmt.Sprintf("%s/v2/%s/manifests/%s", s.URL, repo, tag))
				if err != nil {
					t.Fatalf("parse url: %v", err)
				}
				req, err := http.NewRequest(http.MethodPut, u.String(), io.NopCloser(strings.NewReader(content)))
				if err != nil {
					t.Fatalf("create request: %v", err)
				}
				req.Header.Set("Content-Type", "text/plain")
				resp, err := s.Client().Do(req)
				if err != nil {
					t.Fatalf("put manifest: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("unexpected status: %d", resp.StatusCode)
				}
			}

			err := tag.Tag(strings.Replace(tt.args.imageRef, "ghcr.io", strings.TrimPrefix(s.URL, "https://"), 1), tt.args.newTag, tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Tag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			u, err := url.Parse(fmt.Sprintf("%s/v2/%s/manifests/%s", s.URL, repo, tt.args.newTag))
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				t.Errorf("create request: %v", err)
			}
			resp, err := s.Client().Do(req)
			if err != nil {
				t.Fatalf("put manifest: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("unexpected status: %d", resp.StatusCode)
			}
		})
	}
}
