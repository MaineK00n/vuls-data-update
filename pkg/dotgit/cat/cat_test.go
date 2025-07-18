package cat_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/cat"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestCat(t *testing.T) {
	type args struct {
		repository string
		path       string
		opts       []cat.Option
	}
	tests := []struct {
		name     string
		args     args
		want     string
		hasError bool
	}{
		{
			name: "README.md, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				path:       "README.md",
				opts:       []cat.Option{cat.WithUseNativeGit(true), cat.WithTreeish("main")},
			},
			want: "# vuls-data-raw-test\n",
		},
		{
			name: "README.md, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				path:       "README.md",
				opts:       []cat.Option{cat.WithUseNativeGit(false), cat.WithTreeish("main")},
			},
			want: "# vuls-data-raw-test\n",
		},
		{
			name: "README",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				path:       "README",
				opts:       []cat.Option{cat.WithUseNativeGit(true), cat.WithTreeish("main")},
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.args.repository)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.args.repository, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.args.repository, err)
			}

			got, err := cat.Cat(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst")), tt.args.path, tt.args.opts...)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Cat(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
