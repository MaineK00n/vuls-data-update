package packagemanifest_test

import (
	"path/filepath"
	"strings"
	"testing"

	packageManifest "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/package-manifest"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		wantErr  string
		hasError bool
	}{
		{
			// RHEL 8 and 9 publish the manifest as one page, built with
			// DocBook, where a table is named by the anchor of its title. RHEL
			// 10 publishes a page for each repository, built with DITA-OT,
			// where it is named by the ids of its header cells.
			name: "happy",
		},
		{
			// The page that introduces RHEL 10's repository pages holds no
			// table of its own.
			name:     "no-table",
			wantErr:  "no table found",
			hasError: true,
		},
		{
			// RHEL 9's manifest moved to a page for each repository, with its
			// single page kept: both hold the table of BaseOS.
			name:     "duplicate",
			wantErr:  "duplicate table",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := packageManifest.Fetch(filepath.Join("testdata", "fixtures", tt.name), packageManifest.WithDir(dir))
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
