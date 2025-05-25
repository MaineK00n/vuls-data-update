package find_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/find"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestFind(t *testing.T) {
	type args struct {
		expression string
	}
	tests := []struct {
		name     string
		dotgit   string
		args     args
		treeish  string
		want     []find.FileObject
		hasError bool
	}{
		{
			name:   ".*\\.md",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				expression: ".*\\.md",
			},
			treeish: "main",
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "0100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name:   ".*\\.md",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				expression: ".*\\.md",
			},
			treeish: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "0100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name:   ".*\\.json",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				expression: ".*\\.json",
			},
			treeish: "main",
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.dotgit)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.dotgit, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.dotgit, err)
			}

			got, err := find.Find(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst")), tt.args.expression, find.WithTreeish(tt.treeish))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Find(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
