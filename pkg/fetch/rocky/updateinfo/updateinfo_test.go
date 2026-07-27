package updateinfo_test

import (
	"bytes"
	"io"
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
		{
			// updateinfo.xml.gz whose deflate decodes to valid XML but whose gzip
			// trailer CRC is corrupted. xml.Decode stops before the trailer and
			// succeeds, so only the post-decode drain in fetchUpdateinfo catches
			// the corruption — this case fails without that drain.
			name:     "corruptcrc",
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
	read := func(t *testing.T, name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("testdata", "decompress", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// testdata/decompress/payload is the decompressed content; payload.{gz,xz,zst,bz2}
	// are those same bytes compressed with each real encoder, so every decompress
	// branch is exercised against genuine repodata-style compressed files.
	want := string(read(t, "payload"))

	tests := []struct {
		name    string
		u       string
		file    string
		wantErr bool
	}{
		// Some (vault) repositories serve uncompressed modules.yaml / updateinfo.xml.
		{name: "uncompressed yaml", u: "https://example.com/repodata/abc-modules.yaml", file: "payload"},
		{name: "uncompressed xml", u: "https://example.com/repodata/abc-updateinfo.xml", file: "payload"},
		{name: "gzip", u: "https://example.com/repodata/abc-updateinfo.xml.gz", file: "payload.gz"},
		// Rocky ships modules as *.yaml.xz.
		{name: "xz", u: "https://example.com/repodata/abc-modules.yaml.xz", file: "payload.xz"},
		{name: "zstd", u: "https://example.com/repodata/abc-updateinfo.xml.zst", file: "payload.zst"},
		{name: "bzip2", u: "https://example.com/repodata/abc-updateinfo.xml.bz2", file: "payload.bz2"},
		// Upper-cased filename must still be matched case-insensitively.
		{name: "uppercase gzip filename", u: "https://example.com/repodata/abc-UPDATEINFO.XML.GZ", file: "payload.gz"},
		{name: "unexpected format", u: "https://example.com/repodata/abc.rpm", file: "payload", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dr, err := updateinfo.Decompress(tt.u, bytes.NewReader(read(t, tt.file)))
			if (err != nil) != tt.wantErr {
				t.Fatalf("decompress() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			defer dr.Close()

			got, err := io.ReadAll(dr)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("decompress() = %q, want %q", string(got), want)
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

func Test_isKnownDanglingRef(t *testing.T) {
	tests := []struct {
		name string
		u    string
		want bool
	}{
		{
			// A repomd-referenced updateinfo that is genuinely absent from vault.
			name: "known dangling ref",
			u:    "https://dl.rockylinux.org/vault/rocky/8.6/RT/x86_64/kickstart/repodata/3f851aab6522f26ab8f7e912ff74b62831df3f662ef7596e681628da678054c9-updateinfo.xml.gz",
			want: true,
		},
		{
			// A 404 anywhere else (even in vault) is not silently skipped.
			name: "unlisted vault 404 is not skipped",
			u:    "https://dl.rockylinux.org/vault/rocky/8.6/BaseOS/x86_64/os/repodata/deadbeef-updateinfo.xml.gz",
			want: false,
		},
		{
			name: "live pub repo is not skipped",
			u:    "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/abc-updateinfo.xml.gz",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := updateinfo.IsKnownDanglingRef(tt.u); got != tt.want {
				t.Errorf("isKnownDanglingRef() = %v, want %v", got, tt.want)
			}
		})
	}
}
