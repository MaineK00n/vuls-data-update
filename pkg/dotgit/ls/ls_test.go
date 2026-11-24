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
		// dir is the directory List is given, made under a temporary one, and
		// the dotgit is extracted into it. siblings are directories made beside
		// it.
		dir      string
		siblings []string
		dotgit   string
		want     []string
		hasError bool
	}{
		{
			name:   "vuls-data-raw-test",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want:   []string{"vuls-data-raw-test"},
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
			f, err := os.Open(tt.dotgit)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.dotgit, err)
			}
			defer f.Close()

			parent := t.TempDir()
			for _, s := range tt.siblings {
				if err := os.MkdirAll(filepath.Join(parent, s), 0750); err != nil {
					t.Errorf("mkdir %s. err: %v", s, err)
				}
			}

			dir := filepath.Join(parent, tt.dir)
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.dotgit, err)
			}

			got, err := ls.List(ls.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				rels := make([]string, 0, len(got))
				for _, s := range got {
					rel, err := filepath.Rel(dir, s)
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
