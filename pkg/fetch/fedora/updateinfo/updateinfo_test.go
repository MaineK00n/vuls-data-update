package updateinfo_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora/updateinfo"
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
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/core/updates/6/x86_64/repodata/updateinfo.xml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/core/updates/6/x86_64/repodata/updateinfo.xml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/6/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/core/updates/testing/6/x86_64/repodata/updateinfo.xml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/core/updates/testing/6/x86_64/repodata/updateinfo.xml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/6/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/27/x86_64/repodata/352c3bcc090f7d6e37e7bac80a259d5682a5baf6967242a0b173b263d7af8cbb-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/27/x86_64/repodata/352c3bcc090f7d6e37e7bac80a259d5682a5baf6967242a0b173b263d7af8cbb-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/27/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/27/x86_64/repodata/eaba361c29e430d489e8c9dd3747978be578dffc12ba4b1cf98a8e4904f60ea1-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/27/x86_64/repodata/eaba361c29e430d489e8c9dd3747978be578dffc12ba4b1cf98a8e4904f60ea1-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/27/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/35/Everything/x86_64/repodata/35333f73fb5940a299346fd75ea39336644d767bcb7e12b0234458c44ffba38e-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/35/Everything/x86_64/repodata/35333f73fb5940a299346fd75ea39336644d767bcb7e12b0234458c44ffba38e-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/35/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/35/Modular/x86_64/repodata/5a16b438cba15d33c7741b91f17ab2bd1c368669e53c85882d07c6dcc6cb424f-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/35/Modular/x86_64/repodata/5a16b438cba15d33c7741b91f17ab2bd1c368669e53c85882d07c6dcc6cb424f-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/35/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/35/Everything/x86_64/repodata/c1a94302bc40694f186517c549d982a90fa87460c2f24c2d072e93e284e34c6a-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/35/Everything/x86_64/repodata/c1a94302bc40694f186517c549d982a90fa87460c2f24c2d072e93e284e34c6a-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/35/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/35/Modular/x86_64/repodata/e00c2edf41aeffede082bc8f048ef7b037208d4faf8462391c5a3be8a1378268-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/35/Modular/x86_64/repodata/e00c2edf41aeffede082bc8f048ef7b037208d4faf8462391c5a3be8a1378268-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/35/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/fedora/linux/updates/43/Everything/x86_64/repodata/e09d8b3caedce118e9e23ab4649500c8678cbda905d2bf0c13d81d97895131dc-updateinfo.xml.zst",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/fedora/linux/updates/43/Everything/x86_64/repodata/e09d8b3caedce118e9e23ab4649500c8678cbda905d2bf0c13d81d97895131dc-updateinfo.xml.zst",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/43/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/fedora/linux/updates/testing/43/Everything/x86_64/repodata/97333374229a2a64bc8c6b767924453dc5dac3eb2e847921956216428c6494bb-updateinfo.xml.zst",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/fedora/linux/updates/testing/43/Everything/x86_64/repodata/97333374229a2a64bc8c6b767924453dc5dac3eb2e847921956216428c6494bb-updateinfo.xml.zst",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/43/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/38/x86_64/modules",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/38/x86_64/modules",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/27/s390x/repodata/352c3bcc090f7d6e37e7bac80a259d5682a5baf6967242a0b173b263d7af8cbb-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/27/s390x/repodata/352c3bcc090f7d6e37e7bac80a259d5682a5baf6967242a0b173b263d7af8cbb-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/27/s390x/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/27/s390x/repodata/eaba361c29e430d489e8c9dd3747978be578dffc12ba4b1cf98a8e4904f60ea1-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/27/s390x/repodata/eaba361c29e430d489e8c9dd3747978be578dffc12ba4b1cf98a8e4904f60ea1-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/27/s390x/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/35/Everything/s390x/repodata/c1a94302bc40694f186517c549d982a90fa87460c2f24c2d072e93e284e34c6a-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/35/Everything/s390x/repodata/c1a94302bc40694f186517c549d982a90fa87460c2f24c2d072e93e284e34c6a-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/35/s390x/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/35/Modular/s390x/repodata/e00c2edf41aeffede082bc8f048ef7b037208d4faf8462391c5a3be8a1378268-updateinfo.xml.xz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/35/Modular/s390x/repodata/e00c2edf41aeffede082bc8f048ef7b037208d4faf8462391c5a3be8a1378268-updateinfo.xml.xz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/35/s390x/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/fedora-secondary/updates/43/Everything/s390x/repodata/74f58a91baa4a290e7ab058c6298b46ef49fc5ee990ede14d181340e5d22fca9-updateinfo.xml.zst",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/fedora-secondary/updates/43/Everything/s390x/repodata/74f58a91baa4a290e7ab058c6298b46ef49fc5ee990ede14d181340e5d22fca9-updateinfo.xml.zst",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/43/s390x/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/fedora-secondary/updates/testing/43/Everything/s390x/repodata/97333374229a2a64bc8c6b767924453dc5dac3eb2e847921956216428c6494bb-updateinfo.xml.zst",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/fedora-secondary/updates/testing/43/Everything/s390x/repodata/97333374229a2a64bc8c6b767924453dc5dac3eb2e847921956216428c6494bb-updateinfo.xml.zst",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/43/s390x/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/38/Modular/s390x/repodata/79fd8acbc78883e6c31dc79f0c595d198445143081d4b50d4e295e718a088ba8-modules.yaml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/38/Modular/s390x/repodata/79fd8acbc78883e6c31dc79f0c595d198445143081d4b50d4e295e718a088ba8-modules.yaml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/38/s390x/modules",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/38/Modular/s390x/repodata/79fd8acbc78883e6c31dc79f0c595d198445143081d4b50d4e295e718a088ba8-modules.yaml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/38/Modular/s390x/repodata/79fd8acbc78883e6c31dc79f0c595d198445143081d4b50d4e295e718a088ba8-modules.yaml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "fedora/38/s390x/modules",
		},
		{
			name: "https://dl.fedoraproject.org/pub/archive/epel/7/x86_64/repodata/ee7ce72544e0fca006120c613404d937cc3da9d09c7d80aea269df31639f310c-updateinfo.xml.bz2",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/archive/epel/7/x86_64/repodata/ee7ce72544e0fca006120c613404d937cc3da9d09c7d80aea269df31639f310c-updateinfo.xml.bz2",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "epel/7/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/repodata/a4f5e8b54d8034a5ddb28be23feb2ecad0c81b9d0ed51c4c40a29b1171a9aced-updateinfo.xml.bz2",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/repodata/a4f5e8b54d8034a5ddb28be23feb2ecad0c81b9d0ed51c4c40a29b1171a9aced-updateinfo.xml.bz2",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "epel/8/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/epel/testing/8/Everything/x86_64/repodata/0a9cae41db14e597a17a547b2a0520c7dcd4524092ddba1af60e8700e95a4a8d-updateinfo.xml.bz2",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/epel/testing/8/Everything/x86_64/repodata/0a9cae41db14e597a17a547b2a0520c7dcd4524092ddba1af60e8700e95a4a8d-updateinfo.xml.bz2",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "epel/8/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/epel/next/9/Everything/x86_64/repodata/033a4114a1165553d7fb0abb26a1be367270768874fff3129416cbd65e5b2bc7-updateinfo.xml.bz2",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/epel/next/9/Everything/x86_64/repodata/033a4114a1165553d7fb0abb26a1be367270768874fff3129416cbd65e5b2bc7-updateinfo.xml.bz2",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "epel-next/9/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/epel/testing/next/9/Everything/x86_64/repodata/93cf4560670e3bf30f62255ef8e20496f66893f6ce5f9930c5502037508a1e70-updateinfo.xml.bz2",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/epel/testing/next/9/Everything/x86_64/repodata/93cf4560670e3bf30f62255ef8e20496f66893f6ce5f9930c5502037508a1e70-updateinfo.xml.bz2",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "epel-next/9/x86_64/updateinfo",
		},
		{
			name: "https://dl.fedoraproject.org/pub/epel/8/Modular/x86_64/repodata/b1b3a6319d69628902d5b3997fe97e335933d5567f94a49b3692b1226f7c2adc-modules.yaml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/epel/8/Modular/x86_64/repodata/b1b3a6319d69628902d5b3997fe97e335933d5567f94a49b3692b1226f7c2adc-modules.yaml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "epel/8/x86_64/modules",
		},
		{
			name: "https://dl.fedoraproject.org/pub/epel/testing/8/Modular/x86_64/repodata/b1b3a6319d69628902d5b3997fe97e335933d5567f94a49b3692b1226f7c2adc-modules.yaml.gz",
			args: args{
				u:       "https://dl.fedoraproject.org/pub/epel/testing/8/Modular/x86_64/repodata/b1b3a6319d69628902d5b3997fe97e335933d5567f94a49b3692b1226f7c2adc-modules.yaml.gz",
				baseURL: "https://dl.fedoraproject.org/pub/",
			},
			want: "epel/8/x86_64/modules",
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
