package repository_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/nuclei/repository"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		hasError bool
	}{
		{
			name: "happy",
			args: "./testdata/fixtures",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := repository.Extract(tt.args, repository.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
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

func TestNormalizeCVEID(t *testing.T) {
	tests := []struct {
		name string
		args string
		want string
	}{
		// valid
		{name: "valid CVE ID", args: "CVE-2024-8852", want: "CVE-2024-8852"},
		// lowercase normalization
		{name: "lowercase cve", args: "cve-2024-8852", want: "CVE-2024-8852"},
		// surrounding whitespace
		{name: "trailing space", args: "CVE-2024-8852 ", want: "CVE-2024-8852"},
		// non-CVE (skip)
		{name: "CWE prefix", args: "CWE-200", want: ""},
		{name: "empty", args: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := repository.NormalizeCVEID(tt.args); got != tt.want {
				t.Errorf("NormalizeCVEID(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}
