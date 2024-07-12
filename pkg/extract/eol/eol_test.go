package eol_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/eol"
	eolTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/eol"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		eol      map[string]map[string]map[string]eolTypes.EOL
		hasError bool
	}{
		{
			name: "happy",
			eol: map[string]map[string]map[string]eolTypes.EOL{
				"os": {
					"test": {
						"1": {
							Ended: true,
							Date: map[string]time.Time{
								"main": time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
						"2": {
							Ended: false,
							Date: map[string]time.Time{
								"main": time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
						"3": {
							Ended: false,
							Date: map[string]time.Time{
								"main": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
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

			ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			gp, err := filepath.Abs(dir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}
