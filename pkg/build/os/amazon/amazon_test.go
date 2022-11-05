package amazon_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/amazon"
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
			err := amazon.Build(amazon.WithSrcDir(tt.srcDir), amazon.WithDestVulnDir(filepath.Join(d, "vulnerability")), amazon.WithDestDetectDir(filepath.Join(d, "os")))
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

				if filepath.Base(dir) == "vulnerability" {
					want, err := os.ReadFile(filepath.Join("testdata", "golden", "vulnerability", y, file))
					if err != nil {
						return err
					}

					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Build(). (-expected +got):\n%s", diff)
					}
				} else {
					wantb, err := os.ReadFile(filepath.Join("testdata", "golden", "os", "amazon", filepath.Base(dir), y, file))
					if err != nil {
						return err
					}

					var want build.DetectPackage
					if err := json.Unmarshal(wantb, &want); err != nil {
						return err
					}

					gotb, err := os.ReadFile(path)
					if err != nil {
						return err
					}

					var got build.DetectPackage
					if err := json.Unmarshal(gotb, &got); err != nil {
						return err
					}

					if diff := cmp.Diff(want, got, []cmp.Option{
						cmpopts.SortSlices(func(i, j build.Package) bool {
							return i.Name < j.Name
						})}...); diff != "" {
						t.Errorf("Build(). (-expected +got):\n%s", diff)
					}
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
