package oval_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/build"
	"github.com/MaineK00n/vuls-data-update/pkg/build/os/redhat/oval"
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
			err := oval.Build(oval.WithSrcDir(tt.srcDir), oval.WithDestVulnDir(filepath.Join(d, "vulnerability")), oval.WithDestDetectDir(filepath.Join(d, "os")))
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

				dir1, file := filepath.Split(path)
				dir2, y := filepath.Split(filepath.Clean(dir1))
				if filepath.Base(dir2) == "vulnerability" {
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
					if file == "repository_to_cpe.json" {
						stream := filepath.Base(dir1)

						wantb, err := os.ReadFile(filepath.Join("testdata", "golden", "os", "redhat", "oval", stream[:1], stream, file))
						if err != nil {
							return err
						}

						var want map[string][]string
						if err := json.Unmarshal(wantb, &want); err != nil {
							return err
						}

						gotb, err := os.ReadFile(path)
						if err != nil {
							return err
						}

						var got map[string][]string
						if err := json.Unmarshal(gotb, &got); err != nil {
							return err
						}

						if diff := cmp.Diff(want, got, []cmp.Option{
							cmpopts.SortSlices(func(i, j build.Package) bool {
								return i.Name < j.Name
							})}...); diff != "" {
							t.Errorf("Build(). (-expected +got):\n%s", diff)
						}
					} else {
						stream := filepath.Base(dir2)

						wantb, err := os.ReadFile(filepath.Join("testdata", "golden", "os", "redhat", "oval", stream[:1], stream, y, file))
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
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
