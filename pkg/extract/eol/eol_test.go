package eol_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/eol"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		eol      map[string]map[string]map[string]types.EOLDictionary
		hasError bool
	}{
		{
			name: "happy",
			eol: map[string]map[string]map[string]types.EOLDictionary{
				"os": {
					"test": {
						"1": {
							Ended: true,
							Date: map[string]*time.Time{
								"main": func() *time.Time { t := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC); return &t }(),
							},
						},
						"2": {
							Ended: false,
							Date: map[string]*time.Time{
								"main": func() *time.Time { t := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC); return &t }(),
							},
						},
						"3": {
							Ended: false,
							Date: map[string]*time.Time{
								"main": func() *time.Time { t := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC); return &t }(),
							},
						},
						"4": {
							Ended: false,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := eol.Extract(eol.WithEOL(tt.eol), eol.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
				if err != nil {
					return err
				}

				got, err := os.ReadFile(path)
				if err != nil {
					return err
				}

				if diff := cmp.Diff(string(want), string(got)); diff != "" {
					t.Errorf("Extract(). (-expected +got):\n%s", diff)
				}

				return nil
			}); err != nil {
				t.Error("walk error:", err)
			}
		})
	}
}
