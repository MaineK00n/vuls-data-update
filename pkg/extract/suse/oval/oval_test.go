package oval_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/suse/oval"
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
			// "was already fixed" criterion in a definition not listed in alreadyFixedDefinitions
			name:     "already-fixed-unknown",
			args:     "./testdata/fixtures/already-fixed-unknown",
			hasError: true,
		},
		{
			// definition listed in alreadyFixedDefinitions without a "was already fixed" criterion
			name:     "already-fixed-gone",
			args:     "./testdata/fixtures/already-fixed-gone",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := oval.Extract(utiltest.QueryUnescapeFileTree(t, tt.args), oval.WithDir(dir))
			switch {
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				return
			case err != nil:
				t.Error("unexpected error:", err)
			default:
				ep, err := filepath.Abs(tt.golden)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				gp, err := filepath.Abs(dir)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				utiltest.Diff(t, ep, gp)
			}
		})
	}
}
