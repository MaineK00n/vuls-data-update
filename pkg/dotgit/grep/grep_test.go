package grep_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/grep"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestFind(t *testing.T) {
	type args struct {
		patterns []string
		opts     []grep.Option
	}
	tests := []struct {
		name     string
		dotgit   string
		args     args
		want     []git.GrepResult
		hasError bool
	}{
		{
			name:   "pattern: vuls-data-raw-test",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				patterns: []string{"vuls-data-raw-test"},
				opts: []grep.Option{
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
				},
			},
			want: []git.GrepResult{
				{
					FileName:   "README.md",
					LineNumber: 1,
					Content:    "# vuls-data-raw-test",
					TreeName:   "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
				},
			},
		},
		{
			name:   "pattern: vuls-data-.*",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				patterns: []string{"vuls-data-.*"},
				opts: []grep.Option{
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
				},
			},
			want: []git.GrepResult{
				{
					FileName:   "README.md",
					LineNumber: 1,
					Content:    "# vuls-data-raw-test",
					TreeName:   "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
				},
			},
		},
		{
			name:   "pattern: vuls-data-.*; pathspec: .*.md",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			args: args{
				patterns: []string{"vuls-data-.*"},
				opts: []grep.Option{
					grep.WithTreeish("main"),
					grep.WithPathSpecs([]string{".*.md"}),
				},
			},
			want: []git.GrepResult{
				{
					FileName:   "README.md",
					LineNumber: 1,
					Content:    "# vuls-data-raw-test",
					TreeName:   "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
				},
			},
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

			got, err := grep.Grep(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst")), tt.args.patterns, tt.args.opts...)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Grep(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
