package updateinfo_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/updateinfo"
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

func TestFetch_cyclicTree(t *testing.T) {
	// Every directory listing links a self-descending "loop/" entry and never a
	// repodata/, simulating a cyclic (self-referential symlink) tree. The walk
	// must reach maxDepth and fail rather than loop or return a partial set.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="../">../</a><a href="loop/">loop/</a></body></html>`)
	}))
	defer ts.Close()

	dir := t.TempDir()
	err := updateinfo.Fetch(updateinfo.WithBaseURL(ts.URL), updateinfo.WithDir(dir), updateinfo.WithWait(0))
	if err == nil {
		t.Error("expected error for a cyclic tree that never terminates, got nil")
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
				u:       "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/repodata/106ba7d2cc8d0ba45aebfe29e32dbbc6ac0bb0378413184d62e6198d13fedb76-updateinfo.xml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			want: "almalinux/9/BaseOS/x86_64/os/updateinfo",
		},
		{
			name: "appstream updateinfo",
			args: args{
				u:       "https://repo.almalinux.org/almalinux/10/AppStream/aarch64/os/repodata/cccc125de8ddb7f66ac6a9850f48af285670c3ace1e29f2b0ce002ab69b88ee5-updateinfo.xml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			want: "almalinux/10/AppStream/aarch64/os/updateinfo",
		},
		{
			name: "appstream modules",
			args: args{
				u:       "https://repo.almalinux.org/almalinux/9/AppStream/x86_64/os/repodata/bce3e949236bb3c7f420be2b2c547133aa7183bbe7d6e2f5cc0488d7fb335ac7-modules.yaml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			want: "almalinux/9/AppStream/x86_64/os/modules",
		},
		{
			name: "epel updateinfo (different depth, no os segment)",
			args: args{
				u:       "https://repo.almalinux.org/almalinux-epel/10/x86_64_v2/repodata/2222125de8ddb7f66ac6a9850f48af285670c3ace1e29f2b0ce002ab69b88ee5-updateinfo.xml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			want: "almalinux-epel/10/x86_64_v2/updateinfo",
		},
		{
			name: "vault source repo (logical url of a redirecting tree, no os segment)",
			args: args{
				u:       "https://repo.almalinux.org/vault/8.6/NFV/Source/repodata/c0cace4d6bd977ad29096c46467682b30b7ef65aff60fe7f7238096f9003d898-updateinfo.xml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			want: "vault/8.6/NFV/Source/updateinfo",
		},
		{
			name: "kickstart repodata does not collide with os",
			args: args{
				u:       "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/kickstart/repodata/xxxx-updateinfo.xml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			want: "almalinux/9/BaseOS/x86_64/kickstart/updateinfo",
		},
		{
			name: "unexpected host",
			args: args{
				u:       "https://example.com/almalinux/9/BaseOS/x86_64/os/repodata/updateinfo.xml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			wantErr: true,
		},
		{
			name: "unexpected path",
			args: args{
				u:       "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/repodata/primary.xml.gz",
				baseURL: "https://repo.almalinux.org/",
			},
			wantErr: true,
		},
		{
			name: "dot-segment rejected (path traversal)",
			args: args{
				u:       "https://repo.almalinux.org/almalinux/9/../../../etc/repodata/xxx-updateinfo.xml.gz",
				baseURL: "https://repo.almalinux.org/",
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

func Test_updateinfoPath(t *testing.T) {
	type args struct {
		baseDir string
		id      string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "alma advisory grouped by prefix and year",
			args: args{baseDir: filepath.FromSlash("almalinux/9/BaseOS/x86_64/os/updateinfo"), id: "ALSA-2022:4940"},
			want: filepath.FromSlash("almalinux/9/BaseOS/x86_64/os/updateinfo/ALSA/2022/ALSA-2022:4940.json"),
		},
		{
			name: "dash-separated epel id does not fit the errata shape and is written flat",
			args: args{baseDir: filepath.FromSlash("almalinux-epel/10/x86_64_v2/updateinfo"), id: "FEDORA-EPEL-2024-1a2b3c4d5e"},
			want: filepath.FromSlash("almalinux-epel/10/x86_64_v2/updateinfo/FEDORA-EPEL-2024-1a2b3c4d5e.json"),
		},
		{
			name: "id without a year is written flat",
			args: args{baseDir: filepath.FromSlash("backports/9/updateinfo"), id: "SOMETHING-WEIRD"},
			want: filepath.FromSlash("backports/9/updateinfo/SOMETHING-WEIRD.json"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := updateinfo.UpdateinfoPath(tt.args.baseDir, tt.args.id); got != tt.want {
				t.Errorf("updateinfoPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
