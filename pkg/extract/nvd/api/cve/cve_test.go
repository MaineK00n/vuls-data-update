package cve_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/api/cve"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name        string
		cveDir      string
		cpematchDir string
		golden      string
		hasError    bool
	}{
		{
			name:        "happy",
			cveDir:      "./testdata/fixtures/happy/vuls-data-raw-nvd-api-cve",
			cpematchDir: "./testdata/fixtures/happy/vuls-data-raw-nvd-api-cpematch",
			golden:      "./testdata/golden/happy",
		},
		{
			name:        "with-and",
			cveDir:      "./testdata/fixtures/with-and/vuls-data-raw-nvd-api-cve",
			cpematchDir: "./testdata/fixtures/with-and/vuls-data-raw-nvd-api-cpematch",
			golden:      "./testdata/golden/with-and",
		},
		{
			name:        "with-cpematch",
			cveDir:      "./testdata/fixtures/with-cpematch/vuls-data-raw-nvd-api-cve",
			cpematchDir: "./testdata/fixtures/with-cpematch/vuls-data-raw-nvd-api-cpematch",
			golden:      "./testdata/golden/with-cpematch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := cve.Extract(tt.cveDir, tt.cpematchDir, cve.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			ep, err := filepath.Abs(tt.golden)
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
