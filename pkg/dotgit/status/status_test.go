package status_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/status"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestStatus(t *testing.T) {
	tests := []struct {
		name     string
		dotgit   string
		want     status.DotGitStatus
		hasError bool
	}{
		{
			name:   "vuls-data-raw-test",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			want: status.DotGitStatus{
				Name: "vuls-data-raw-test",
				Time: time.Now(),
				Size: struct {
					Total  int64 "json:\"total\""
					DotGit int64 "json:\"dotgit\""
				}{
					Total:  27009,
					DotGit: 27009,
				},
				Restored: false,
			},
		},
		{
			name:   "vuls-data-raw-test-restored",
			dotgit: "testdata/fixtures/vuls-data-raw-test-restored.tar.zst",
			want: status.DotGitStatus{
				Name: "vuls-data-raw-test-restored",
				Time: time.Now(),
				Size: struct {
					Total  int64 "json:\"total\""
					DotGit int64 "json:\"dotgit\""
				}{
					Total:  27030,
					DotGit: 27009,
				},
				Restored: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.dotgit)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.dotgit, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.dotgit, err)
			}

			got, err := status.Status(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst")))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				relpath, err := filepath.Rel(dir, got.Name)
				if err != nil {
					t.Errorf("unexpected err: %v", err)
				}
				got.Name = relpath
				if diff := cmp.Diff(tt.want, got, cmpopts.EquateApproxTime(2*time.Second)); diff != "" {
					t.Errorf("Status(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
