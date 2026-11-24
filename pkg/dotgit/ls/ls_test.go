package ls_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/ls"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestList(t *testing.T) {
	tests := []struct {
		name string
		// dir is the directory List is given, relative to a temporary one the
		// call is made from, and the dotgit, when there is one, is extracted
		// into it. siblings are directories made beside it. file makes dir an
		// empty file instead.
		dir      string
		siblings []string
		dotgit   string
		file     bool
		want     []string
		hasError bool
	}{
		{
			name:   "vuls-data-raw-test",
			dir:    "dotgit",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want:   []string{"vuls-data-raw-test"},
		},
		{
			// As before a first pull.
			name: "dir that does not exist",
			dir:  "missing",
			want: []string{},
		},
		{
			// An empty dir is the directory the call is made from.
			name:   "empty dir",
			dir:    "",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want:   []string{"vuls-data-raw-test"},
		},
		{
			// dir is cleaned as filepath.Join cleans it: missing/../dotgit is
			// dotgit, though missing does not exist.
			name:   "dir that is not clean",
			dir:    "missing/../dotgit",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want:   []string{"vuls-data-raw-test"},
		},
		{
			// Unlike a missing dir, one that cannot be read is an error.
			name:     "dir that is a file",
			dir:      "file",
			file:     true,
			hasError: true,
		},
		{
			// dir is a path, not a pattern: dotgit[1] must not list what
			// dotgit1 holds.
			name:     "dir holding a character class",
			dir:      "dotgit[1]",
			siblings: []string{filepath.Join("dotgit1", "vuls-data-raw-other")},
			dotgit:   "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want:     []string{"vuls-data-raw-test"},
		},
		{
			name:   "dir holding an unclosed bracket",
			dir:    "dotgit[",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want:   []string{"vuls-data-raw-test"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			for _, s := range tt.siblings {
				if err := os.MkdirAll(filepath.Join(parent, s), 0750); err != nil {
					t.Errorf("mkdir %s. err: %v", s, err)
				}
			}

			dir := filepath.Join(parent, tt.dir)
			if tt.dotgit != "" {
				f, err := os.Open(tt.dotgit)
				if err != nil {
					t.Errorf("open %s. err: %v", tt.dotgit, err)
				}
				defer f.Close()

				if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst"))); err != nil {
					t.Errorf("extract %s. err: %v", tt.dotgit, err)
				}
			}
			if tt.file {
				f, err := os.Create(dir)
				if err != nil {
					t.Errorf("create %s. err: %v", dir, err)
				}
				f.Close()
			}

			// dir is given relative to the directory the call is made from, as
			// a --dir typed on the command line is. The move comes after the
			// setup, whose fixture path is relative to the package directory.
			t.Chdir(parent)

			got, err := ls.List(ls.WithDir(tt.dir))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				rels := make([]string, 0, len(got))
				for _, s := range got {
					rel, err := filepath.Rel(tt.dir, s)
					if err != nil {
						t.Errorf("unexpected err: %v", err)
					}
					rels = append(rels, rel)
				}

				if diff := cmp.Diff(tt.want, rels); diff != "" {
					t.Errorf("List(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
