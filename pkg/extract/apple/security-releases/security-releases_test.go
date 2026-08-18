package securityreleases_test

import (
	"path/filepath"
	"testing"

	securityreleases "github.com/MaineK00n/vuls-data-update/pkg/extract/apple/security-releases"
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
			name:     "unexpected_macos_major",
			args:     "./testdata/fixtures/unexpected_macos_major",
			hasError: true,
		},
		{
			name:     "unexpected_os_family",
			args:     "./testdata/fixtures/unexpected_os_family",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := securityreleases.Extract(tt.args, securityreleases.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
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
