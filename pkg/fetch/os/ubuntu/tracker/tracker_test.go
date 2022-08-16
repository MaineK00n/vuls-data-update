package tracker_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/tracker"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/ubuntu-security-tracker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := tracker.Fetch(tracker.WithRepoURL(tt.testdata), tracker.WithDir(dir), tracker.WithRetry(0))
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
				_, v := filepath.Split(filepath.Clean(dir))
				wantb, err := os.ReadFile(filepath.Join("testdata", "golden", v, y, file))
				if err != nil {
					return err
				}
				var want tracker.Advisory
				if err := json.Unmarshal(wantb, &want); err != nil {
					return err
				}

				gotb, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				var got tracker.Advisory
				if err := json.Unmarshal(gotb, &got); err != nil {
					return err
				}

				opts := []cmp.Option{
					cmpopts.SortSlices(func(i, j tracker.Package) bool {
						return i.Name < j.Name
					}),
				}
				if diff := cmp.Diff(want, got, opts...); diff != "" {
					t.Errorf("Fetch(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
