package oracle_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/oracle"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name        string
		fixturePath string
		goldenPath  string
		hasError    bool
	}{
		{
			name:        "happy",
			fixturePath: "./testdata/fixtures/happy",
			goldenPath:  "./testdata/golden/happy",
		},
		{
			name:        "modularitylabel",
			fixturePath: "./testdata/fixtures/modularitylabel",
			goldenPath:  "./testdata/golden/modularitylabel",
		},
		// Based on "modularitylabel" case, the regexp pattern of module stream is altered and others are identical
		{
			name:        "modularitylabel-stream-reversed",
			fixturePath: "./testdata/fixtures/modularitylabel-stream-reversed",
			goldenPath:  "./testdata/golden/modularitylabel-stream-reversed",
		},
		{
			name:        "majormixed",
			fixturePath: "./testdata/fixtures/majormixed",
			goldenPath:  "./testdata/golden/majormixed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy files under fixturePath to temp dir to convert query-escaped names to normal ones

			outputDir := t.TempDir()
			err := oracle.Extract(inputDir, oracle.WithDir(outputDir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			ep, err := filepath.Abs(tt.goldenPath)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			gp, err := filepath.Abs(outputDir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}
