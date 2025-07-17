package grep_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/grep"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestFind(t *testing.T) {
	type args struct {
		repository string
		patterns   []string
		opts       []grep.Option
	}
	tests := []struct {
		name     string
		args     args
		want     string
		hasError bool
	}{
		{
			name: "pattern: vuls-data-raw-test, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-raw-test"},
				opts: []grep.Option{
					grep.WithUseNativeGit(true),
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
				},
			},
			want: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab:README.md:1:# vuls-data-raw-test\n",
		},
		{
			name: "pattern: vuls-data-raw-test, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-raw-test"},
				opts: []grep.Option{
					grep.WithUseNativeGit(false),
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
				},
			},
			want: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab:README.md:1:# vuls-data-raw-test\n",
		},
		{
			name: "pattern: vuls-data-raw-test, --files-with-matches, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-raw-test"},
				opts: []grep.Option{
					grep.WithUseNativeGit(true),
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
					grep.WithFilesWithMatches(true),
				},
			},
			want: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab:README.md\n",
		},
		{
			name: "pattern: vuls-data-raw-test, --files-with-matches, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-raw-test"},
				opts: []grep.Option{
					grep.WithUseNativeGit(false),
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
					grep.WithFilesWithMatches(true),
				},
			},
			want: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab:README.md\n",
		},
		{
			name: "pattern: vuls-data-.*, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-.*"},
				opts: []grep.Option{
					grep.WithUseNativeGit(true),
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
				},
			},
			want: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab:README.md:1:# vuls-data-raw-test\n",
		},
		{
			name: "pattern: vuls-data-.*, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-.*"},
				opts: []grep.Option{
					grep.WithUseNativeGit(false),
					grep.WithTreeish("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"),
				},
			},
			want: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab:README.md:1:# vuls-data-raw-test\n",
		},
		{
			name: "pattern: vuls-data-.*; pathspec: *.md, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-.*"},
				opts: []grep.Option{
					grep.WithUseNativeGit(true),
					grep.WithTreeish("main"),
					grep.WithPathSpecs([]string{"*.md"}),
				},
			},
			want: "main:README.md:1:# vuls-data-raw-test\n",
		},
		{
			name: "pattern: vuls-data-.*; pathspec: .*.md, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				patterns:   []string{"vuls-data-.*"},
				opts: []grep.Option{
					grep.WithUseNativeGit(false),
					grep.WithTreeish("main"),
					grep.WithPathSpecs([]string{".*.md"}),
				},
			},
			want: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab:README.md:1:# vuls-data-raw-test\n",
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

			got, err := grep.Grep(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst")), tt.args.patterns, tt.args.opts...)
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
