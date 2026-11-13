package contains_test

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/contains"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util/test/git"
)

func TestContains(t *testing.T) {
	type args struct {
		repository string
		commit     string
		opts       []contains.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "contains full commit hash, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
				opts:       []contains.Option{contains.WithUseNativeGit(true)},
			},
		},
		{
			name: "contains short commit hash, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d48",
				opts:       []contains.Option{contains.WithUseNativeGit(true)},
			},
		},
		{
			name: "contains short commit hash, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d48",
				opts:       []contains.Option{contains.WithUseNativeGit(false)},
			},
		},
		{
			name: "not contains commit hash, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac",
				opts:       []contains.Option{contains.WithUseNativeGit(true)},
			},
			wantErr: true,
		},
		{
			name: "not contains commit hash, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac",
				opts:       []contains.Option{contains.WithUseNativeGit(false)},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.args.repository)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.args.repository, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.args.repository, err)
			}

			err = contains.Contains(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst")), tt.args.commit, tt.args.opts...)
			switch {
			case err != nil && !tt.wantErr:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.wantErr:
				t.Error("expected error has not occurred")
			}
		})
	}
}

// The commits of testdata/fixtures/history, oldest first, and the tree of the
// first.
const (
	commit1 = "a841a4b11e592afb4d574f86c5de63ad95d1567a"
	commit2 = "321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54"
	commit3 = "7ff21bf293f2763a9e10872f0debf6726fd125ff"
	commit4 = "f71e70526a42ab5a02c0db48c0ab002cae190c6a"
	tree1   = "da97fdaef51513ed29f81a64cea431c351d4532e"
)

func TestContainsWithBranch(t *testing.T) {
	// The fixture is commits 1-4 in a line. main is moved back to 3, and other
	// is at 4, so 4 is only on other. shallow is a clone of depth 2, as
	// vuls-data-db truncates a dotgit: it has 2-4, and 2 is shallow.
	dir := t.TempDir()
	full, err := git.Populate(dir, "testdata/fixtures/history")
	if err != nil {
		t.Fatalf("populate. err: %v", err)
	}
	hashes, err := git.CommitHashes(full)
	if err != nil {
		t.Fatalf("commit hashes. err: %v", err)
	}
	if diff := cmp.Diff([]string{commit1, commit2, commit3, commit4}, hashes); diff != "" {
		t.Fatalf("commit hashes. (-expected +got):\n%s", diff)
	}
	if tree := strings.TrimSpace(run(t, "-C", full, "rev-parse", fmt.Sprintf("%s^{tree}", commit1))); tree != tree1 {
		t.Fatalf("tree of commit 1. expected: %q, actual: %q", tree1, tree)
	}
	run(t, "-C", full, "branch", "other", commit4)
	run(t, "-C", full, "update-ref", "refs/heads/main", commit3)

	shallow := filepath.Join(dir, "shallow")
	run(t, "clone", "--quiet", "--origin", "origin", "--depth", "2", "--no-single-branch", "--no-tags", "--no-checkout", (&url.URL{Scheme: "file", Path: full}).String(), shallow)
	run(t, "-C", shallow, "branch", "--quiet", "other", "origin/other")
	if bs, err := os.ReadFile(filepath.Join(shallow, ".git", "shallow")); err != nil || string(bs) != fmt.Sprintf("%s\n", commit2) {
		t.Fatalf("shallow commits. expected: %q, actual: %q, err: %v", fmt.Sprintf("%s\n", commit2), bs, err)
	}

	type args struct {
		// repository is "full", "shallow", or "missing" for a path that does
		// not exist.
		repository string
		commit     string
		branch     string
	}
	tests := []struct {
		name string
		args args
		// wantErr is the sentinel error the error wraps. With hasError, nil
		// means it wraps none of them.
		wantErr  error
		hasError bool
	}{
		{
			name: "the tip of the branch",
			args: args{repository: "full", commit: commit3, branch: "main"},
		},
		{
			name: "behind the tip of the branch",
			args: args{repository: "full", commit: commit1, branch: "main"},
		},
		{
			name: "abbreviated hash",
			args: args{repository: "full", commit: commit2[:7], branch: "main"},
		},
		{
			name: "abbreviated hash in upper case",
			args: args{repository: "full", commit: strings.ToUpper(commit2[:7]), branch: "main"},
		},
		{
			name: "the tip of another branch",
			args: args{repository: "full", commit: commit4, branch: "other"},
		},
		{
			name:     "only on another branch",
			args:     args{repository: "full", commit: commit4, branch: "main"},
			wantErr:  contains.ErrNotReachable,
			hasError: true,
		},
		{
			name:     "a tree, not a commit",
			args:     args{repository: "full", commit: tree1, branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
		},
		{
			name:     "missing commit",
			args:     args{repository: "full", commit: "0123456789abcdef0123456789abcdef01234567", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
		},
		{
			name:     "missing branch",
			args:     args{repository: "full", commit: commit1, branch: "nightly"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
		},
		{
			name:     "full ref name as the branch",
			args:     args{repository: "full", commit: commit1, branch: "refs/heads/main"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
		},
		{
			name:     "HEAD as the branch",
			args:     args{repository: "full", commit: commit1, branch: "HEAD"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
		},
		{
			// Read as a revision, main~1 would be commit 2.
			name:     "revision as the branch",
			args:     args{repository: "full", commit: commit2, branch: "main~1"},
			hasError: true,
		},
		{
			name:     "option as the branch",
			args:     args{repository: "full", commit: commit1, branch: "--all"},
			hasError: true,
		},
		{
			name:     "revision as the commit",
			args:     args{repository: "full", commit: "main~1", branch: "main"},
			hasError: true,
		},
		{
			name:     "option as the commit",
			args:     args{repository: "full", commit: "--all", branch: "main"},
			hasError: true,
		},
		{
			name:     "hash shorter than 4 hex digits",
			args:     args{repository: "full", commit: commit2[:3], branch: "main"},
			hasError: true,
		},
		{
			name: "no branch, only on another branch",
			args: args{repository: "full", commit: commit4},
		},
		{
			name: "no branch, revision",
			args: args{repository: "full", commit: "main~1"},
		},
		{
			name:     "no branch, missing commit",
			args:     args{repository: "full", commit: "0123456789abcdef0123456789abcdef01234567"},
			hasError: true,
		},
		{
			name: "shallow, the shallow commit",
			args: args{repository: "shallow", commit: commit2, branch: "main"},
		},
		{
			name:     "shallow, only on another branch",
			args:     args{repository: "shallow", commit: commit4, branch: "main"},
			wantErr:  contains.ErrNotReachable,
			hasError: true,
		},
		{
			name:     "shallow, truncated",
			args:     args{repository: "shallow", commit: commit1, branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
		},
		{
			name:     "not a repository",
			args:     args{repository: "missing", commit: commit1, branch: "main"},
			hasError: true,
		},
	}
	for _, tt := range tests {
		for _, native := range []bool{true, false} {
			name := fmt.Sprintf("%s, go-git", tt.name)
			if native {
				name = fmt.Sprintf("%s, native git", tt.name)
			}
			t.Run(name, func(t *testing.T) {
				repository := map[string]string{
					"full":    full,
					"shallow": shallow,
					"missing": filepath.Join(dir, "missing"),
				}[tt.args.repository]

				err := contains.Contains(repository, tt.args.commit, contains.WithBranch(tt.args.branch), contains.WithUseNativeGit(native))
				switch {
				case err != nil && !tt.hasError:
					t.Errorf("unexpected err: %v", err)
				case err == nil && tt.hasError:
					t.Error("expected error has not occurred")
				case err != nil:
					for _, sentinel := range []error{contains.ErrBranchNotFound, contains.ErrCommitNotFound, contains.ErrNotReachable} {
						if got, want := errors.Is(err, sentinel), sentinel == tt.wantErr; got != want {
							t.Errorf("errors.Is(err, %q). expected: %t, actual: %t, err: %v", sentinel, want, got, err)
						}
					}
				}
			})
		}
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
