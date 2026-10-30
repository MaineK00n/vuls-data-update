package truncate_test

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/truncate"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util/test/git"
)

func TestTruncate(t *testing.T) {
	type args struct {
		depth  int
		origin string
		exists bool
	}
	type want struct {
		branches map[string]int
		shallow  []int
		origin   string
	}
	tests := []struct {
		name     string
		args     args
		want     want
		hasError bool
	}{
		{
			name: "depth 1",
			args: args{
				depth:  1,
				origin: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
			},
			want: want{
				branches: map[string]int{"main": 1, "nightly": 1},
				shallow:  []int{2, 3},
				origin:   "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
			},
		},
		{
			name: "deeper than the history",
			args: args{
				depth:  5,
				origin: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
			},
			want: want{
				branches: map[string]int{"main": 3, "nightly": 2},
				origin:   "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
			},
		},
		{
			name: "no origin",
			args: args{
				depth: 1,
			},
			want: want{
				branches: map[string]int{"main": 1, "nightly": 1},
				shallow:  []int{2, 3},
			},
		},
		{
			name: "depth 0",
			args: args{
				depth: 0,
			},
			hasError: true,
		},
		{
			name: "already exists",
			args: args{
				depth:  1,
				exists: true,
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			src, err := git.Populate(dir, "testdata/fixtures/history")
			if err != nil {
				t.Fatalf("populate. err: %v", err)
			}
			hashes, err := git.CommitHashes(src)
			if err != nil {
				t.Fatalf("commit hashes. err: %v", err)
			}
			run(t, "-C", src, "branch", "nightly", hashes[1])
			run(t, "-C", src, "tag", "v1", hashes[0])
			if tt.args.origin != "" {
				run(t, "-C", src, "remote", "add", "origin", tt.args.origin)
			}
			if tt.args.exists {
				if err := os.MkdirAll(filepath.Join(dir, "truncated", filepath.Base(src)), 0755); err != nil {
					t.Fatalf("mkdir. err: %v", err)
				}
			}

			got, err := truncate.Truncate(src, truncate.WithDir(filepath.Join(dir, "truncated")), truncate.WithDepth(tt.args.depth))
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				if want := filepath.Join(dir, "truncated", filepath.Base(src)); got != want {
					t.Errorf("Truncate(). expected: %q, actual: %q", want, got)
				}

				branches := make(map[string]int)
				for name := range strings.Lines(run(t, "-C", got, "for-each-ref", "--format=%(refname:lstrip=2)", "refs/heads/")) {
					name = strings.TrimSuffix(name, "\n")
					n, err := strconv.Atoi(strings.TrimSpace(run(t, "-C", got, "rev-list", "--count", "refs/heads/"+name)))
					if err != nil {
						t.Fatalf("parse commit count. err: %v", err)
					}
					branches[name] = n
				}
				if diff := cmp.Diff(tt.want.branches, branches); diff != "" {
					t.Errorf("branches. (-expected +got):\n%s", diff)
				}

				var shallow []string
				switch bs, err := os.ReadFile(filepath.Join(got, ".git", "shallow")); {
				case err == nil:
					shallow = strings.Fields(string(bs))
					slices.Sort(shallow)
				case !errors.Is(err, fs.ErrNotExist):
					t.Fatalf("read shallow. err: %v", err)
				}
				var wantShallow []string
				for _, i := range tt.want.shallow {
					wantShallow = append(wantShallow, hashes[i-1])
				}
				slices.Sort(wantShallow)
				if diff := cmp.Diff(wantShallow, shallow); diff != "" {
					t.Errorf("shallow. (-expected +got):\n%s", diff)
				}

				if tags := run(t, "-C", got, "tag", "--list"); tags != "" {
					t.Errorf("tags. expected: none, actual: %q", tags)
				}

				if origin := strings.TrimSpace(run(t, "-C", got, "config", "--default", "", "--get", "remote.origin.url")); origin != tt.want.origin {
					t.Errorf("origin. expected: %q, actual: %q", tt.want.origin, origin)
				}

				if files := run(t, "-C", got, "ls-files"); files != "README.md\n" {
					t.Errorf("index. expected: %q, actual: %q", "README.md\n", files)
				}
			}
		})
	}
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	bs, err := cmd.Output()
	if err != nil {
		t.Fatalf("exec %q. err: %v", cmd.String(), err)
	}
	return string(bs)
}
