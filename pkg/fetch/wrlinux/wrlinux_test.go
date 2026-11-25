package wrlinux_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util/test/git"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/wrlinux"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		wantErr  string
		hasError bool
	}{
		{
			name:     "happy",
			testdata: "testdata/fixtures/happy/windriver-cve-tracker",
		},
		{
			// HarfBuzz::Shaper, a Perl module, puts colons in the package
			// name, so a status line is split at ": ", not at the first ":".
			name:     "colon-package",
			testdata: "testdata/fixtures/colon-package/windriver-cve-tracker",
		},
		{
			// A status line names the package of its section. One under
			// Patches_go that names golang, whose section comes later, fails
			// rather than writing into a map that was never made.
			name:     "package-mismatch",
			testdata: "testdata/fixtures/package-mismatch/windriver-cve-tracker",
			wantErr:  `unexpected package. expected: "go", actual: "golang"`,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := git.Populate(t.TempDir(), tt.testdata)
			if err != nil {
				t.Errorf("git init. err: %v", err)
			}

			dir := t.TempDir()
			err = wrlinux.Fetch(wrlinux.WithRepoURL(d), wrlinux.WithDir(dir), wrlinux.WithRetry(0))
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("Fetch() error = %v, want it to contain %q", err, tt.wantErr)
			}
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden", tt.name), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
