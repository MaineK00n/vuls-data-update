package errata_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/alma/errata"
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
		// Synthetic kernel advisories: CVEs listed again by a newer minor's
		// advisory after being fixed by an older minor's (9.7, 9.8 -> 9.9,
		// 9.2 -> 9.4 with 9.3 absent, the kernel-rt source package of 8.8 ->
		// 8.10, the stripped 10.2 -> 10.3).
		{
			name:   "kernel",
			args:   "./testdata/fixtures/kernel",
			golden: "./testdata/golden/kernel",
		},
		// bpftool of 9.9 older than bpftool of 9.8: the ranges around 9.8's
		// fix cannot be ordered.
		{
			name:     "kernel-unordered",
			args:     "./testdata/fixtures/kernel-unordered",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			fixturePath, err := utiltest.QueryUnescapeFileTree(t.TempDir(), tt.args)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			err = errata.Extract(fixturePath, errata.WithDir(dir))
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
