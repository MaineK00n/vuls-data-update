package errata_test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/alma/errata"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		hasError bool
	}{
		{
			name: "happy",
			args: "./testdata/fixtures",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := errata.Extract(tt.args, errata.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				dir, y := filepath.Split(filepath.Clean(dir))
				f, err := os.Open(filepath.Join("testdata", "golden", filepath.Base(dir), y, file))
				if err != nil {
					return err
				}
				defer f.Close()

				var want types.Data
				if err := json.NewDecoder(f).Decode(&want); err != nil {
					return err
				}

				f, err = os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()

				var got types.Data
				if err := json.NewDecoder(f).Decode(&got); err != nil {
					return err
				}

				opts := []cmp.Option{
					cmpopts.SortSlices(func(a, b types.Vulnerability) bool {
						return a.ID < b.ID
					}),
					cmpopts.SortSlices(func(a, b detection.Detection) bool {
						if a.Package.Name == b.Package.Name {
							return fmt.Sprintf("%s", a.Package.Architectures) < fmt.Sprintf("%s", b.Package.Architectures)
						}
						return a.Package.Name < b.Package.Name
					}),
					cmpopts.SortSlices(func(a, b reference.Reference) bool {
						return a.URL < b.URL
					}),
				}
				if diff := cmp.Diff(want, got, opts...); diff != "" {
					t.Errorf("Extract(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
