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
		opts     []status.Option
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
		{
			name:   "vuls-data-raw-test, git",
			dotgit: "testdata/fixtures/vuls-data-raw-test.tar.zst",
			opts:   []status.Option{status.WithGit(true)},
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
				Git: &status.Git{
					Branches: map[string]status.Branch{
						"main": {
							Commit:  "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
							Commits: 1,
						},
					},
					Disk: status.Disk{
						All:  225,
						Tips: 225,
					},
				},
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

			got, err := status.Status(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst")), tt.opts...)
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
