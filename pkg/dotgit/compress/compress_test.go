package compress_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/compress"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util/test/git"
)

func TestCompress(t *testing.T) {
	tests := []struct {
		name     string
		root     string
		datapath string
		golden   string
		hasError bool
	}{
		{
			name:     "vuls-data-raw-redhat-ovalv2",
			root:     "vuls-data-raw-redhat-ovalv2",
			datapath: "testdata/fixtures/vuls-data-raw-redhat-ovalv2",
			golden:   "testdata/golden/vuls-data-raw-redhat-ovalv2.tar.zst",
		},
		{
			name:     "vuls-data-raw-redhat-ovalv2-archive-1",
			root:     "vuls-data-raw-redhat-ovalv2",
			datapath: "testdata/fixtures/vuls-data-raw-redhat-ovalv2",
			golden:   "testdata/golden/vuls-data-raw-redhat-ovalv2-archive-1.tar.zst",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			d, err := git.Populate(dir, tt.datapath)
			if err != nil {
				t.Errorf("git init. err: %v", err)
			}

			err = compress.Compress(d, filepath.Join(dir, filepath.Base(tt.golden)), compress.WithRoot(tt.root))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				f, err := os.Open(filepath.Join(dir, filepath.Base(tt.golden)))
				if err != nil {
					t.Errorf("read file. err: %v", err)
				}
				defer f.Close()

				if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, "got", tt.root)); err != nil {
					t.Errorf("extract. err: %v", err)
				}

				got, err := git.CommitHashes(filepath.Join(dir, "got", tt.root))
				if err != nil {
					t.Errorf("commit hashes. err: %v", err)
				}

				f, err = os.Open(tt.golden)
				if err != nil {
					t.Errorf("read file. err: %v", err)
				}
				defer f.Close()

				if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, "want", tt.root)); err != nil {
					t.Errorf("extract. err: %v", err)
				}

				want, err := git.CommitHashes(filepath.Join(dir, "want", tt.root))
				if err != nil {
					t.Errorf("commit hashes. err: %v", err)
				}

				if diff := cmp.Diff(got, want); diff != "" {
					t.Errorf("Compress(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
