package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestExtractDotgitTarZst(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		want     []string
		hasError bool
	}{
		{
			name:    "happy",
			fixture: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want: []string{
				"vuls-data-raw-test",
				"vuls-data-raw-test/.git", "vuls-data-raw-test/.git/COMMIT_EDITMSG", "vuls-data-raw-test/.git/FETCH_HEAD", "vuls-data-raw-test/.git/HEAD", "vuls-data-raw-test/.git/config", "vuls-data-raw-test/.git/description", "vuls-data-raw-test/.git/index",
				"vuls-data-raw-test/.git/hooks", "vuls-data-raw-test/.git/hooks/applypatch-msg.sample", "vuls-data-raw-test/.git/hooks/commit-msg.sample", "vuls-data-raw-test/.git/hooks/fsmonitor-watchman.sample", "vuls-data-raw-test/.git/hooks/post-update.sample", "vuls-data-raw-test/.git/hooks/pre-applypatch.sample", "vuls-data-raw-test/.git/hooks/pre-commit.sample", "vuls-data-raw-test/.git/hooks/pre-merge-commit.sample", "vuls-data-raw-test/.git/hooks/pre-push.sample", "vuls-data-raw-test/.git/hooks/pre-rebase.sample", "vuls-data-raw-test/.git/hooks/pre-receive.sample", "vuls-data-raw-test/.git/hooks/prepare-commit-msg.sample", "vuls-data-raw-test/.git/hooks/push-to-checkout.sample", "vuls-data-raw-test/.git/hooks/sendemail-validate.sample", "vuls-data-raw-test/.git/hooks/update.sample",
				"vuls-data-raw-test/.git/info", "vuls-data-raw-test/.git/info/exclude",
				"vuls-data-raw-test/.git/logs", "vuls-data-raw-test/.git/logs/HEAD", "vuls-data-raw-test/.git/logs/refs", "vuls-data-raw-test/.git/logs/refs/heads", "vuls-data-raw-test/.git/logs/refs/heads/main",
				"vuls-data-raw-test/.git/objects", "vuls-data-raw-test/.git/objects/40", "vuls-data-raw-test/.git/objects/40/3164dbcb94dfb2b004ce50fc619c1351bbd37e", "vuls-data-raw-test/.git/objects/46", "vuls-data-raw-test/.git/objects/46/df57e1de336181a027385cf5ce993bba78db3a", "vuls-data-raw-test/.git/objects/9d", "vuls-data-raw-test/.git/objects/9d/3d5d486d4c9414321a2df56f2e007c4c2c8fab", "vuls-data-raw-test/.git/objects/info", "vuls-data-raw-test/.git/objects/pack",
				"vuls-data-raw-test/.git/refs", "vuls-data-raw-test/.git/refs/heads", "vuls-data-raw-test/.git/refs/heads/main", "vuls-data-raw-test/.git/refs/tags"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			f, err := os.Open(tt.fixture)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.fixture, err)
			}
			defer f.Close() //nolint:errcheck

			err = ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.fixture), ".tar.zst")))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				var got []string
				if err := filepath.WalkDir(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.fixture), ".tar.zst")), func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}

					p, err := filepath.Rel(dir, path)
					if err != nil {
						return err
					}

					got = append(got, p)

					return nil
				}); err != nil {
					t.Errorf("walk dir. err: %v", err)
				}

				if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(i, j string) bool {
					return i < j
				})); diff != "" {
					t.Errorf("Pull(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
