package oval_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/ubuntu/oval"
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
			fixturePath: "./testdata/fixtures/",
			goldenPath:  "./testdata/golden/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputDir := t.TempDir()
			err := oval.Extract(utiltest.QueryUnescapeFileTree(t, tt.fixturePath), oval.WithDir(outputDir))
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
