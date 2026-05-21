package v2_test

import (
	"path/filepath"
	"testing"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/v2"
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
			name:        "semver-range",
			cveDir:      "./testdata/fixtures/semver-range/vuls-data-raw-nvd-feed-cve-v2",
			cpematchDir: "./testdata/fixtures/semver-range/vuls-data-raw-nvd-feed-cpematch-v2",
			golden:      "./testdata/golden/semver-range",
		},
		{
			name:        "non-semver-range",
			cveDir:      "./testdata/fixtures/non-semver-range/vuls-data-raw-nvd-feed-cve-v2",
			cpematchDir: "./testdata/fixtures/non-semver-range/vuls-data-raw-nvd-feed-cpematch-v2",
			golden:      "./testdata/golden/non-semver-range",
		},
		{
			name:        "exact-match",
			cveDir:      "./testdata/fixtures/exact-match/vuls-data-raw-nvd-feed-cve-v2",
			cpematchDir: "./testdata/fixtures/exact-match/vuls-data-raw-nvd-feed-cpematch-v2",
			golden:      "./testdata/golden/exact-match",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := v2.Extract(tt.cveDir, tt.cpematchDir, v2.WithDir(dir))
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
