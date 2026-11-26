package cwe_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/mitre/cwe"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		golden   string
		hasError bool
	}{
		{
			name:   "happy",
			args:   "./testdata/fixtures/happy",
			golden: "./testdata/golden/happy",
		},
		{
			// raw written before CWE 5.0 support has its groupings under category/
			name:     "pre-5.0 category",
			args:     "./testdata/fixtures/pre-5.0-category",
			hasError: true,
		},
		{
			// raw written before CWE 5.0 support has a single phase per introduction
			name:     "pre-5.0 phase",
			args:     "./testdata/fixtures/pre-5.0-phase",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := cwe.Extract(tt.args, cwe.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(tt.golden, dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
