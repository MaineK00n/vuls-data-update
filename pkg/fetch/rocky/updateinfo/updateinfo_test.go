package updateinfo_test

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/rocky/updateinfo"
)

func TestFetch(t *testing.T) {
	type args struct {
		opts []updateinfo.Option
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
		},
		{
			// An advisory id that does not fit the <prefix>-<year>:<seq> shape
			// must fail the fetch rather than be written somewhere unvalidated.
			name:     "badid",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, filepath.Join("testdata", "fixtures", tt.name, r.URL.Path))
			}))
			defer ts.Close()

			dir := t.TempDir()
			opts := append([]updateinfo.Option{updateinfo.WithBaseURL(ts.URL), updateinfo.WithDir(dir), updateinfo.WithWait(0)}, tt.args.opts...)
			err := updateinfo.Fetch(opts...)
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
					want, err := os.ReadFile(filepath.Join("testdata", "golden", tt.name, dir, url.QueryEscape(file)))
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

func Test_toDir(t *testing.T) {
	type args struct {
		u       string
		baseURL string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "baseos updateinfo",
			args: args{
				u:       "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/106ba7d2cc8d0ba45aebfe29e32dbbc6ac0bb0378413184d62e6198d13fedb76-updateinfo.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			want: "pub/rocky/9/BaseOS/x86_64/os/updateinfo",
		},
		{
			name: "appstream updateinfo",
			args: args{
				u:       "https://dl.rockylinux.org/pub/rocky/10/AppStream/aarch64/os/repodata/cccc125de8ddb7f66ac6a9850f48af285670c3ace1e29f2b0ce002ab69b88ee5-updateinfo.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			want: "pub/rocky/10/AppStream/aarch64/os/updateinfo",
		},
		{
			name: "appstream modules (xz)",
			args: args{
				u:       "https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/repodata/11a979380c1b87ab61dd547f52e1d891a43362c407a1a47c4031d6bea903057d-modules.yaml.xz",
				baseURL: "https://dl.rockylinux.org/",
			},
			want: "pub/rocky/9/AppStream/x86_64/os/modules",
		},
		{
			name: "sig updateinfo (different depth, repository after arch)",
			args: args{
				u:       "https://dl.rockylinux.org/pub/sig/9/cloud/x86_64/cloud-common/repodata/2222125de8ddb7f66ac6a9850f48af285670c3ace1e29f2b0ce002ab69b88ee5-updateinfo.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			want: "pub/sig/9/cloud/x86_64/cloud-common/updateinfo",
		},
		{
			name: "vault source repo (logical url of a redirecting tree)",
			args: args{
				u:       "https://dl.rockylinux.org/vault/rocky/8.6/BaseOS/source/tree/repodata/c0cace4d6bd977ad29096c46467682b30b7ef65aff60fe7f7238096f9003d898-updateinfo.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			want: "vault/rocky/8.6/BaseOS/source/tree/updateinfo",
		},
		{
			name: "kickstart repodata does not collide with os",
			args: args{
				u:       "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/kickstart/repodata/xxxx-updateinfo.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			want: "pub/rocky/9/BaseOS/x86_64/kickstart/updateinfo",
		},
		{
			// A few Rocky SIG repositories publish upper-cased updateinfo filenames.
			name: "uppercase updateinfo filename (sig repo)",
			args: args{
				u:       "https://dl.rockylinux.org/pub/sig/8/cloud/aarch64/cloud-kernel/repodata/bb99f09e-2129-409f-a7f2-46f8727b0685-UPDATEINFO.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			want: "pub/sig/8/cloud/aarch64/cloud-kernel/updateinfo",
		},
		{
			name: "unexpected host",
			args: args{
				u:       "https://example.com/pub/rocky/9/BaseOS/x86_64/os/repodata/updateinfo.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			wantErr: true,
		},
		{
			name: "unexpected path",
			args: args{
				u:       "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/primary.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			wantErr: true,
		},
		{
			name: "dot-segment rejected (path traversal)",
			args: args{
				u:       "https://dl.rockylinux.org/pub/rocky/9/../../../etc/repodata/xxx-updateinfo.xml.gz",
				baseURL: "https://dl.rockylinux.org/",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := updateinfo.ToDir(tt.args.u, tt.args.baseURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("toDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("toDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decompress(t *testing.T) {
	gz := func(t *testing.T, b []byte) []byte {
		t.Helper()
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	payload := []byte("document: modulemd\nversion: 2\n")
	tests := []struct {
		name    string
		u       string
		body    func(*testing.T) []byte
		want    string
		wantErr bool
	}{
		{
			// Some (vault) repositories serve uncompressed modules.yaml.
			name: "uncompressed yaml",
			u:    "https://example.com/repodata/abc-modules.yaml",
			body: func(_ *testing.T) []byte { return payload },
			want: string(payload),
		},
		{
			name: "uncompressed xml",
			u:    "https://example.com/repodata/abc-updateinfo.xml",
			body: func(_ *testing.T) []byte { return payload },
			want: string(payload),
		},
		{
			name: "gzip",
			u:    "https://example.com/repodata/abc-updateinfo.xml.gz",
			body: func(t *testing.T) []byte { return gz(t, payload) },
			want: string(payload),
		},
		{
			// Upper-cased filename must still be recognized as gzip.
			name: "uppercase gzip filename",
			u:    "https://example.com/repodata/abc-UPDATEINFO.XML.GZ",
			body: func(t *testing.T) []byte { return gz(t, payload) },
			want: string(payload),
		},
		{
			name:    "unexpected format",
			u:       "https://example.com/repodata/abc.rpm",
			body:    func(_ *testing.T) []byte { return payload },
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := updateinfo.Decompress(tt.u, bytes.NewReader(tt.body(t)))
			if (err != nil) != tt.wantErr {
				t.Fatalf("decompress() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.String() != tt.want {
				t.Errorf("decompress() = %q, want %q", got.String(), tt.want)
			}
		})
	}
}

func Test_ModuleStreamVersion(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int64
		wantErr bool
	}{
		{name: "integer", in: "version: 9040020240101000000", want: 9040020240101000000},
		// Some Rocky vault modules quote the stream version as a string.
		{name: "quoted string", in: `version: "9010020230330221931"`, want: 9010020230330221931},
		{name: "non-numeric string", in: `version: "not-a-number"`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var md updateinfo.Modulemd
			err := yaml.Unmarshal([]byte(tt.in), &md)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if int64(md.Version) != tt.want {
				t.Errorf("Version = %d, want %d", int64(md.Version), tt.want)
			}
		})
	}
}
