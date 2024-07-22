package oracle_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/oracle"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name       string
		args       string
		goldenPath string
		hasError   bool
	}{
		{
			name:       "happy",
			args:       "./testdata/fixtures/happy",
			goldenPath: "./testdata/golden/happy",
		},
		{
			name:       "modularitylabel",
			args:       "./testdata/fixtures/modularitylabel",
			goldenPath: "./testdata/golden/modularitylabel",
		},
		{
			name:       "modularitylabel-stream-reversed",
			args:       "./testdata/fixtures/modularitylabel-stream-reversed",
			goldenPath: "./testdata/golden/modularitylabel-stream-reversed",
		},
		{
			name:       "majormixed",
			args:       "./testdata/fixtures/majormixed",
			goldenPath: "./testdata/golden/majormixed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := oracle.Extract(tt.args, oracle.WithDir(dir))
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
			gp, err := filepath.Abs(dir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}
