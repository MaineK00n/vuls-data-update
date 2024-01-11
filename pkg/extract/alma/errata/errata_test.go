package errata_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/alma/errata"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/affected"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/reference"
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
				dir, v := filepath.Split(filepath.Clean(dir))
				f, err := os.Open(filepath.Join("testdata", "golden", filepath.Base(dir), v, y, file))
				if err != nil {
					return err
				}
				defer f.Close()

				var want types.Info
				if err := json.NewDecoder(f).Decode(&want); err != nil {
					return err
				}

				f, err = os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()

				var got types.Info
				if err := json.NewDecoder(f).Decode(&got); err != nil {
					return err
				}

				opts := []cmp.Option{
					cmpopts.SortSlices(func(a, b affectedTypes.Affected) bool {
						if a.Package.Name == b.Package.Name {
							return strings.Join(a.Package.Arches, ", ") < strings.Join(b.Package.Arches, ", ")
						}
						return a.Package.Name < b.Package.Name
					}),
					cmpopts.SortSlices(func(a, b referenceTypes.Reference) bool {
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
