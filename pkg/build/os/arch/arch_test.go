package arch_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/build/os/arch"
	"github.com/google/go-cmp/cmp"
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
			d := t.TempDir()
			err := arch.Build(arch.WithSrcDir(tt.srcDir), arch.WithDestVulnDir(filepath.Join(d, "vulnerability")), arch.WithDestDetectDir(filepath.Join(d, "os")))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.Walk(d, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				dir, y := filepath.Split(filepath.Clean(dir))

				var want []byte
				if filepath.Base(dir) == "vulnerability" {
					want, err = os.ReadFile(filepath.Join("testdata", "golden", "vulnerability", y, file))
					if err != nil {
						return err
					}
				} else {
					want, err = os.ReadFile(filepath.Join("testdata", "golden", "os", "arch", y, file))
					if err != nil {
						return err
					}
				}

				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Build(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
