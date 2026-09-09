package tracker_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/tracker"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test/git"
)

func TestFetch(t *testing.T) {
	tests := []struct {
		name     string
		testdata string
		hasError bool
	}{
		{
			name:     "happy path",
			testdata: "testdata/fixtures/ubuntu-cve-tracker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := git.Populate(t.TempDir(), tt.testdata)
			if err != nil {
				t.Errorf("git init. err: %v", err)
			}

			dir := t.TempDir()
			err = tracker.Fetch(tracker.WithRepoURL(d), tracker.WithDir(dir), tracker.WithRetry(0))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				utiltest.Diff(t, filepath.Join("testdata", "golden"), dir)
			}
		})
	}
}
