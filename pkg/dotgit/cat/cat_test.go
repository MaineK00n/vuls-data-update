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
		path string
	}
	tests := []struct {
		name     string
		dotgit   string
		args     args
		treeish  string
		want     string
		hasError bool
	}{
		{
			name:   "README.md",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				path: "README.md",
			},
			treeish: "main",
			want:    "# vuls-data-raw-test\n",
		},
		{
			name:   "README",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				path: "README",
			},
			treeish:  "main",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.dotgit)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.dotgit, err)
			}
			defer f.Close() //nolint:errcheck

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.dotgit, err)
			}

			got, err := cat.Cat(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst")), tt.args.path, cat.WithTreeish(tt.treeish))
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
