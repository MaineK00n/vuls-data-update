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
		{
			// The last 3 of 5 commits, with nightly a commit behind main, and a
			// tag at a commit off nightly that no branch reaches. disk.all
			// counts the history and the tagged commit, disk.tips only what
			// main and nightly point to.
			name:   "vuls-data-raw-test-history, git",
			dotgit: "testdata/fixtures/vuls-data-raw-test-history.tar.zst",
			opts:   []status.Option{status.WithGit(true)},
			want: status.DotGitStatus{
				Name: "vuls-data-raw-test-history",
				Time: time.Now(),
				Size: struct {
					Total  int64 "json:\"total\""
					DotGit int64 "json:\"dotgit\""
				}{
					Total:  3598,
					DotGit: 3598,
				},
				Restored: false,
				Git: &status.Git{
					Branches: map[string]status.Branch{
						"main": {
							Commit:  "c44bf638c45cc9a462e0512fc2fa6f270a8b43ac",
							Commits: 3,
						},
						"nightly": {
							Commit:  "38e1051040da14c6c755d3847adeb65f1cc9c98c",
							Commits: 2,
						},
					},
					Shallow: []string{"121cb97c243d9ed2c704cac2f282398ed7046ea9"},
					Disk: status.Disk{
						All:  950,
						Tips: 476,
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
