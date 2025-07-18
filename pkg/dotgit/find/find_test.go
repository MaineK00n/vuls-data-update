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
		repository string
		expression string
		opts       []find.Option
	}
	tests := []struct {
		name     string
		args     args
		want     []find.FileObject
		hasError bool
	}{
		{
			name: ".*\\.md, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("main")},
			},
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name: ".*\\.md, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("main")},
			},
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
			name: ".*\\.md, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab")},
			},
			want: []find.FileObject{
				{
					Name: "README.md",
					Mode: "100644",
					Type: "blob",
					Hash: "46df57e1de336181a027385cf5ce993bba78db3a",
					Size: 21,
				},
			},
		},
		{
			name: ".*\\.md, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.md",
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab")},
			},
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
			name: ".*\\.json, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.json",
				opts:       []find.Option{find.WithUseNativeGit(true), find.WithTreeish("main")},
			},
			want: nil,
		},
		{
			name: ".*\\.json, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				expression: ".*\\.json",
				opts:       []find.Option{find.WithUseNativeGit(false), find.WithTreeish("main")},
			},
			want: nil,
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

			got, err := find.Find(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst")), tt.args.expression, tt.args.opts...)
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
