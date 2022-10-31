package nvd_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/build/other/nvd"
)

func TestBuild(t *testing.T) {
	tests := []struct {
		name     string
		srcDir   string
		hasError bool
	}{
		{
			name:   "happy path",
			srcDir: "testdata/fixtures",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destVulnDir := t.TempDir()
			destDetectDir := t.TempDir()
			err := nvd.Build(nvd.WithSrcDir(tt.srcDir), nvd.WithDestVulnDir(destVulnDir), nvd.WithDestDetectDir(destDetectDir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			for key, dir := range map[string]string{"vulnerability": destVulnDir, "cpe": destDetectDir} {
				if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
					if err != nil {
						return err
					}

					if info.IsDir() {
						return nil
					}

					dir, file := filepath.Split(path)
					want, err := os.ReadFile(filepath.Join("testdata", "golden", key, filepath.Base(dir), file))
					if err != nil {
						return err
					}

					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Fetch(). (-expected +got):\n%s", diff)
					}

					return nil
				}); err != nil {
					t.Error("walk error:", err)
				}
			}
		})
	}
}
