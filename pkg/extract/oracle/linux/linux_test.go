package linux_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/oracle/linux"
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
			name:   "modularitylabel",
			args:   "./testdata/fixtures/modularitylabel",
			golden: "./testdata/golden/modularitylabel",
		},
		// Based on "modularitylabel" case, the regexp pattern of module stream is altered and others are identical
		{
			name:   "modularitylabel-stream-reversed",
			args:   "./testdata/fixtures/modularitylabel-stream-reversed",
			golden: "./testdata/golden/modularitylabel-stream-reversed",
		},
		{
			name:   "majormixed",
			args:   "./testdata/fixtures/majormixed",
			golden: "./testdata/golden/majormixed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			fixturePath, err := utiltest.QueryUnescapeFileTree(t.TempDir(), tt.args)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			err = linux.Extract(fixturePath, linux.WithDir(dir))
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
