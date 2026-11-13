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

func TestContainsWithBranch(t *testing.T) {
	// The fixture is commits 1-4 in a line. main is moved back to 3, and other
	// is at 4, so 4 is only on other. shallow is a clone of depth 2, as
	// vuls-data-db truncates a dotgit: it has 2-4, and 2 is shallow. Then full
	// gets an annotated tag of 1, a branch and a tag at 3 named like a hash of
	// no object, and a tag at 4 named like the full ref name of a branch.
	dir := t.TempDir()
	full, err := git.Populate(dir, "testdata/fixtures/history")
	if err != nil {
		t.Fatalf("populate. err: %v", err)
	}
	hashes, err := git.CommitHashes(full)
	if err != nil {
		t.Fatalf("commit hashes. err: %v", err)
	}
	if diff := cmp.Diff([]string{
		"a841a4b11e592afb4d574f86c5de63ad95d1567a", // commit 1
		"321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54", // commit 2
		"7ff21bf293f2763a9e10872f0debf6726fd125ff", // commit 3
		"f71e70526a42ab5a02c0db48c0ab002cae190c6a", // commit 4
	}, hashes); diff != "" {
		t.Fatalf("commit hashes. (-expected +got):\n%s", diff)
	}
	// The tree of commit 1.
	if tree := strings.TrimSpace(run(t, "-C", full, "rev-parse", "a841a4b11e592afb4d574f86c5de63ad95d1567a^{tree}")); tree != "da97fdaef51513ed29f81a64cea431c351d4532e" {
		t.Fatalf("tree of commit 1. expected: %q, actual: %q", "da97fdaef51513ed29f81a64cea431c351d4532e", tree)
	}
	run(t, "-C", full, "branch", "other", "f71e70526a42ab5a02c0db48c0ab002cae190c6a")               // commit 4
	run(t, "-C", full, "update-ref", "refs/heads/main", "7ff21bf293f2763a9e10872f0debf6726fd125ff") // commit 3

	shallow := filepath.Join(dir, "shallow")
	run(t, "clone", "--quiet", "--origin", "origin", "--depth", "2", "--no-single-branch", "--no-tags", "--no-checkout", (&url.URL{Scheme: "file", Path: full}).String(), shallow)
	run(t, "-C", shallow, "branch", "--quiet", "other", "origin/other")
	// Commit 2 is the shallow commit.
	if bs, err := os.ReadFile(filepath.Join(shallow, ".git", "shallow")); err != nil || string(bs) != "321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54\n" {
		t.Fatalf("shallow commits. expected: %q, actual: %q, err: %v", "321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54\n", bs, err)
	}

	// An annotated tag of commit 1. The tagger and the date are fixed, and the
	// machine's git config is left out, so the tag has the same hash every
	// time.
	cmd := exec.Command("git", "-C", full, "tag", "--annotate", "--message", "v1", "v1", "a841a4b11e592afb4d574f86c5de63ad95d1567a")
	cmd.Env = append(os.Environ(), fmt.Sprintf("GIT_CONFIG_GLOBAL=%s", os.DevNull), "GIT_CONFIG_NOSYSTEM=1", "GIT_COMMITTER_NAME=GitHub Actions", "GIT_COMMITTER_EMAIL=action@github.com", "GIT_COMMITTER_DATE=2025-01-05T00:00:00Z")
	if bs, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exec %q. err: %v, output: %q", cmd.String(), err, bs)
	}
	if tag := strings.TrimSpace(run(t, "-C", full, "rev-parse", "refs/tags/v1")); tag != "3132226146d484fc47138777803926be1a8ce34a" {
		t.Fatalf("annotated tag of commit 1. expected: %q, actual: %q", "3132226146d484fc47138777803926be1a8ce34a", tag)
	}
	// A branch and a tag at commit 3, named like a hash of no object.
	run(t, "-C", full, "update-ref", "refs/heads/89abcdef0123456789abcdef0123456789abcdef", "7ff21bf293f2763a9e10872f0debf6726fd125ff")
	run(t, "-C", full, "update-ref", "refs/tags/89abcdef0123456789abcdef0123456789abcdef", "7ff21bf293f2763a9e10872f0debf6726fd125ff")
	// A tag at commit 4 named refs/heads/release, the full ref name of a
	// branch that does not exist.
	run(t, "-C", full, "update-ref", "refs/tags/refs/heads/release", "f71e70526a42ab5a02c0db48c0ab002cae190c6a")

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
		// msg, if set, is the message of the error, on both paths.
		msg string
		// exitError is whether, on native git, the error holds the
		// *exec.ExitError of the git that failed.
		exitError bool
	}{
		{
			// Commit 3.
			name: "the tip of the branch",
			args: args{repository: "full", commit: "7ff21bf293f2763a9e10872f0debf6726fd125ff", branch: "main"},
		},
		{
			// Commit 1.
			name: "behind the tip of the branch",
			args: args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "main"},
		},
		{
			// Commit 2.
			name: "hash in upper case",
			args: args{repository: "full", commit: "321CC453FA66E6D7F6EC5D5BDB64C5767D67FB54", branch: "main"},
		},
		{
			// Commit 4.
			name: "the tip of another branch",
			args: args{repository: "full", commit: "f71e70526a42ab5a02c0db48c0ab002cae190c6a", branch: "other"},
		},
		{
			// Commit 4.
			name:     "only on another branch",
			args:     args{repository: "full", commit: "f71e70526a42ab5a02c0db48c0ab002cae190c6a", branch: "main"},
			wantErr:  contains.ErrNotReachable,
			hasError: true,
			msg:      "check f71e70526a42ab5a02c0db48c0ab002cae190c6a is reachable from refs/heads/main: commit not reachable from branch",
		},
		{
			// The tree of commit 1. Neither rev-parse nor ResolveRevision tells
			// it from a missing object.
			name:     "a tree, not a commit",
			args:     args{repository: "full", commit: "da97fdaef51513ed29f81a64cea431c351d4532e", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "resolve da97fdaef51513ed29f81a64cea431c351d4532e (the history may have been truncated or rewritten): commit not found",
		},
		{
			// The tag v1, which resolves to commit 1.
			name:     "an annotated tag, not a commit",
			args:     args{repository: "full", commit: "3132226146d484fc47138777803926be1a8ce34a", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "3132226146d484fc47138777803926be1a8ce34a resolves to commit a841a4b11e592afb4d574f86c5de63ad95d1567a, but is not a commit's own full hash (e.g. an annotated tag's hash, an abbreviation or a ref name): commit not found",
		},
		{
			name:     "missing commit",
			args:     args{repository: "full", commit: "0123456789abcdef0123456789abcdef01234567", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "resolve 0123456789abcdef0123456789abcdef01234567 (the history may have been truncated or rewritten): commit not found",
		},
		{
			// native git reads the hash as the missing object. go-git falls back
			// to the branch of that name, at commit 3, whose hash is not the
			// one given. So the messages differ.
			name:     "missing commit, with a branch and a tag of its name",
			args:     args{repository: "full", commit: "89abcdef0123456789abcdef0123456789abcdef", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
		},
		{
			// Commit 1, then the first 24 digits of commit 2.
			name:     "hash of 64 hex digits in a SHA-1 repository",
			args:     args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a321cc453fa66e6d7f6ec5d5b", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "resolve a841a4b11e592afb4d574f86c5de63ad95d1567a321cc453fa66e6d7f6ec5d5b (the history may have been truncated or rewritten): commit not found",
		},
		{
			// Commit 1.
			name:     "missing branch",
			args:     args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "nightly"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
			msg:      "check refs/heads/nightly exists: branch not found",
		},
		{
			// Commit 1. Read as a revision, refs/heads/foo-1-gf71e7052 is describe
			// output for commit 4, which contains commit 1.
			name:     "missing branch named like describe output",
			args:     args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "foo-1-gf71e7052"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
			msg:      "check refs/heads/foo-1-gf71e7052 exists: branch not found",
		},
		{
			// Commit 1. Read as a revision, refs/heads/release is the tag of that
			// name, at commit 4, which contains commit 1.
			name:     "missing branch, with a tag named refs/heads/<branch>",
			args:     args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "release"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
			msg:      "check refs/heads/release exists: branch not found",
		},
		{
			// Commit 1.
			name:     "full ref name as the branch",
			args:     args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "refs/heads/main"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
			msg:      "check refs/heads/refs/heads/main exists: branch not found",
		},
		{
			// Commit 1.
			name:     "HEAD as the branch",
			args:     args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "HEAD"},
			wantErr:  contains.ErrBranchNotFound,
			hasError: true,
			msg:      "check refs/heads/HEAD exists: branch not found",
		},
		{
			// Commit 2. Read as a revision, main~1 would be commit 2.
			name:     "revision as the branch",
			args:     args{repository: "full", commit: "321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54", branch: "main~1"},
			hasError: true,
			msg:      `validate branch "main~1": invalid reference name`,
		},
		{
			// Commit 1.
			name:     "option as the branch",
			args:     args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "--all"},
			hasError: true,
			msg:      `validate branch "--all": invalid reference name`,
		},
		{
			// main~1 is commit 2.
			name:     "revision as the commit",
			args:     args{repository: "full", commit: "main~1", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "main~1 resolves to commit 321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54, but is not a commit's own full hash (e.g. an annotated tag's hash, an abbreviation or a ref name): commit not found",
		},
		{
			name:     "option as the commit",
			args:     args{repository: "full", commit: "--all", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "resolve --all (the history may have been truncated or rewritten): commit not found",
		},
		{
			// Commit 2, abbreviated.
			name:     "abbreviated hash",
			args:     args{repository: "full", commit: "321cc45", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "321cc45 resolves to commit 321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54, but is not a commit's own full hash (e.g. an annotated tag's hash, an abbreviation or a ref name): commit not found",
		},
		{
			// Commit 4.
			name: "no branch, only on another branch",
			args: args{repository: "full", commit: "f71e70526a42ab5a02c0db48c0ab002cae190c6a"},
		},
		{
			name: "no branch, revision",
			args: args{repository: "full", commit: "main~1"},
		},
		{
			// The tree of commit 1: without a branch, any name of an object
			// counts.
			name: "no branch, tree name",
			args: args{repository: "full", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a^{tree}"},
		},
		{
			// Callers tell a missing commit by the exit status of native git.
			name:      "no branch, missing commit",
			args:      args{repository: "full", commit: "0123456789abcdef0123456789abcdef01234567"},
			hasError:  true,
			exitError: true,
		},
		{
			// Commit 2.
			name: "shallow, the shallow commit",
			args: args{repository: "shallow", commit: "321cc453fa66e6d7f6ec5d5bdb64c5767d67fb54", branch: "main"},
		},
		{
			// Commit 4.
			name:     "shallow, only on another branch",
			args:     args{repository: "shallow", commit: "f71e70526a42ab5a02c0db48c0ab002cae190c6a", branch: "main"},
			wantErr:  contains.ErrNotReachable,
			hasError: true,
			msg:      "check f71e70526a42ab5a02c0db48c0ab002cae190c6a is reachable from refs/heads/main: commit not reachable from branch",
		},
		{
			// Commit 1.
			name:     "shallow, truncated",
			args:     args{repository: "shallow", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "main"},
			wantErr:  contains.ErrCommitNotFound,
			hasError: true,
			msg:      "resolve a841a4b11e592afb4d574f86c5de63ad95d1567a (the history may have been truncated or rewritten): commit not found",
		},
		{
			// Commit 1.
			name:     "not a repository",
			args:     args{repository: "missing", commit: "a841a4b11e592afb4d574f86c5de63ad95d1567a", branch: "main"},
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
					if tt.msg != "" && err.Error() != tt.msg {
						t.Errorf("message. expected: %q, actual: %q", tt.msg, err.Error())
					}
					if _, ok := errors.AsType[*exec.ExitError](err); native && tt.exitError && !ok {
						t.Errorf("errors.AsType[*exec.ExitError](err). expected: true, actual: false, err: %v", err)
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
