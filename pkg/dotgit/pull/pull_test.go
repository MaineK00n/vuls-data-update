package pull_test

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/contains"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/pull"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestPull(t *testing.T) {
	type args struct {
		repository string
		opts       []pull.Option
	}
	tests := []struct {
		name   string
		args   args
		golden string
		// wantHead, if set, is what .git/HEAD of the pulled repository
		// holds: a commit hash when the checkout detached HEAD.
		wantHead string
		// wantFiles, if set, are files of the pulled repository and their
		// contents.
		wantFiles map[string]string
		hasError  bool
		// wantErr is how the error begins.
		wantErr string
		// wantErrHas, if set, is a part of the error after wantErr: the
		// switch command that failed and the start of what git said.
		wantErrHas string
		// wantCommitNotFound is whether errors.Is matches the error with
		// contains.ErrCommitNotFound, as it does for a target that is not in
		// the repository.
		wantCommitNotFound bool
		// wantExitCode, if set, is the exit status of git that the error
		// wraps: that of switch, whose error stays in the chain.
		wantExitCode int
	}{
		{
			name: "vuls-data-raw-test restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithRestore(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: main, restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main"), pull.WithRestore(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: HEAD, restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("HEAD"), pull.WithRestore(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: v0.0.1, restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.1"), pull.WithRestore(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fab, restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"), pull.WithRestore(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test restore: true",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithRestore(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: main, restore: true",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main"), pull.WithRestore(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			// A fetch that writes nothing back leaves every file deleted, and
			// the pull that would put them back has to survive that state.
			name: "vuls-data-raw-test-emptied restore: true",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-emptied",
				opts:       []pull.Option{pull.WithRestore(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test-emptied.tar.zst",
		},
		{
			// A commit behind the branch, as a lock file pins one: the
			// initial commit has the README.md that main deletes.
			name: "vuls-data-raw-test-emptied checkout: b9b8cec27035fddf3c7addcf7b76c8dda6be5e76, restore: true",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-emptied",
				opts:       []pull.Option{pull.WithCheckout("b9b8cec27035fddf3c7addcf7b76c8dda6be5e76"), pull.WithRestore(true)},
			},
			golden:    "testdata/golden/vuls-data-raw-test-emptied-b9b8cec-restored.tar.zst",
			wantHead:  "b9b8cec27035fddf3c7addcf7b76c8dda6be5e76",
			wantFiles: map[string]string{"README.md": "# vuls-data-raw-test\n"},
		},
		{
			// A name that switch accepts and cat-file -e does not, as with
			// "-" for the previous branch: the merge base of main and v0.0.1.
			name: "vuls-data-raw-test checkout: main...v0.0.1, restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main...v0.0.1"), pull.WithRestore(false)},
			},
			golden:   "testdata/golden/vuls-data-raw-test.tar.zst",
			wantHead: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
		},
		{
			// A target that is there but is not a commit: contains finds it,
			// so the error of switch is returned as it is.
			name: "vuls-data-raw-test checkout: v0.0.1^{tree}, restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.1^{tree}"), pull.WithRestore(false)},
			},
			hasError:     true,
			wantErr:      "switch to v0.0.1^{tree}: ",
			wantErrHas:   `switch --detach v0.0.1^{tree}", stderr: "fatal: `,
			wantExitCode: 128,
		},
		{
			// A commit pinned before vuls-data-db truncated the history is
			// no longer in the repository.
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac (not in the repository), restore: true",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fac"), pull.WithRestore(true)},
			},
			hasError:           true,
			wantErr:            "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten: switch to 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac: ",
			wantErrHas:         `switch --detach 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac", stderr: "fatal: `,
			wantExitCode:       128,
			wantCommitNotFound: true,
		},
		{
			// A tag that is not in the repository.
			name: "vuls-data-raw-test checkout: v0.0.2 (not in the repository), restore: true",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.2"), pull.WithRestore(true)},
			},
			hasError:           true,
			wantErr:            "v0.0.2 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten: switch to v0.0.2: ",
			wantErrHas:         `switch --detach v0.0.2", stderr: "fatal: `,
			wantExitCode:       128,
			wantCommitNotFound: true,
		},
		{
			// rev-parse is not asked about a name that switch reads
			// otherwise, so the error of switch is returned as it is.
			name: "vuls-data-raw-test checkout: - (no previous branch), restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("-"), pull.WithRestore(false)},
			},
			hasError:     true,
			wantErr:      "switch to -: ",
			wantErrHas:   `switch --detach -", stderr: "fatal: `,
			wantExitCode: 128,
		},
		{
			name: "vuls-data-raw-test checkout: main...v0.0.2 (no v0.0.2), restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main...v0.0.2"), pull.WithRestore(false)},
			},
			hasError:     true,
			wantErr:      "switch to main...v0.0.2: ",
			wantErrHas:   `switch --detach main...v0.0.2", stderr: "fatal: `,
			wantExitCode: 128,
		},
		{
			// A blob that is there, which no branch or tag can name. rev-parse
			// would read the ^{object} it is asked with as part of the path,
			// and find nothing, so it is not asked, and the error of switch is
			// returned as it is.
			name: "vuls-data-raw-test checkout: main:README.md, restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main:README.md"), pull.WithRestore(false)},
			},
			hasError:     true,
			wantErr:      "switch to main:README.md: ",
			wantErrHas:   `switch --detach main:README.md", stderr: "fatal: `,
			wantExitCode: 128,
		},
		{
			name: "vuls-data-raw-test-archive-1 restore: false",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-archive-1",
				opts:       []pull.Option{pull.WithRestore(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test-archive-1.tar.zst",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The in-memory network routes every host, ghcr.io included, to
			// the test server, so the fixtures keep their production image
			// references.
			ts := httptest.NewTestServer(t, registry.New())

			originalTransport := http.DefaultTransport
			http.DefaultTransport = ts.Client().Transport
			t.Cleanup(func() {
				http.DefaultTransport = originalTransport
			})

			repo, err := remote.NewRepository(tt.args.repository)
			if err != nil {
				t.Fatalf("new repository: %v", err)
			}

			if err := setup(fmt.Sprintf("%s/%s", repo.Reference.Registry, repo.Reference.Repository)); err != nil {
				t.Fatalf("setup: %v", err)
			}

			dir := t.TempDir()
			err = pull.Pull(repo.Reference.String(), append([]pull.Option{pull.WithDir(dir)}, tt.args.opts...)...)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil:
				if !strings.HasPrefix(err.Error(), tt.wantErr) {
					t.Errorf("Pull() error does not begin with %q, error: %v", tt.wantErr, err)
				}
				if !strings.Contains(err.Error(), tt.wantErrHas) {
					t.Errorf("Pull() error does not hold %q, error: %v", tt.wantErrHas, err)
				}
				if got := errors.Is(err, contains.ErrCommitNotFound); got != tt.wantCommitNotFound {
					t.Errorf("errors.Is(Pull() error, contains.ErrCommitNotFound). expected: %t, actual: %t, error: %v", tt.wantCommitNotFound, got, err)
				}
				if tt.wantExitCode != 0 {
					if ee := (*exec.ExitError)(nil); !errors.As(err, &ee) || ee.ExitCode() != tt.wantExitCode {
						t.Errorf("Pull() error does not wrap the exit status %d of git, error: %v", tt.wantExitCode, err)
					}
				}
			default:
				var got []string
				if err := filepath.WalkDir(filepath.Join(dir, "ghcr.io", "vulsio", "vuls-data-db"), func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}

					p, err := filepath.Rel(filepath.Join(dir, "ghcr.io", "vulsio", "vuls-data-db"), path)
					if err != nil {
						return err
					}

					if p == "." {
						return nil
					}

					got = append(got, p)

					return nil
				}); err != nil {
					t.Errorf("walk dir. err: %v", err)
				}

				var want []string
				f, err := os.Open(tt.golden)
				if err != nil {
					t.Errorf("open %s. err: %v", tt.golden, err)
				}
				defer f.Close()

				r, err := zstd.NewReader(f)
				if err != nil {
					t.Errorf("new zstd reader. err: %v", err)
				}
				defer r.Close()

				tr := tar.NewReader(r)
				for {
					hdr, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Errorf("next tar reader. err: %v", err)
					}
					want = append(want, filepath.Clean(hdr.Name))
				}

				if diff := cmp.Diff(want, got, cmpopts.SortSlices(func(i, j string) bool {
					return i < j
				})); diff != "" {
					t.Errorf("Pull(). (-expected +got):\n%s", diff)
				}

				if tt.wantHead != "" {
					switch bs, err := os.ReadFile(filepath.Join(dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference, ".git", "HEAD")); {
					case err != nil:
						t.Errorf("read HEAD. err: %v", err)
					case strings.TrimSpace(string(bs)) != tt.wantHead:
						t.Errorf("HEAD. expected: %q, actual: %q", tt.wantHead, strings.TrimSpace(string(bs)))
					}
				}

				for name, content := range tt.wantFiles {
					switch bs, err := os.ReadFile(filepath.Join(dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference, name)); {
					case err != nil:
						t.Errorf("read %s. err: %v", name, err)
					case string(bs) != content:
						t.Errorf("%s. expected: %q, actual: %q", name, content, string(bs))
					}
				}
			}
		})
	}
}

// TestPullWithoutGit checks that a target git cannot be run to check out is
// not reported as not in the repository: rev-parse cannot tell, so the error
// of switch is returned as it is.
func TestPullWithoutGit(t *testing.T) {
	ts := httptest.NewTestServer(t, registry.New())

	originalTransport := http.DefaultTransport
	http.DefaultTransport = ts.Client().Transport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})

	repo, err := remote.NewRepository("ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test")
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}

	if err := setup(fmt.Sprintf("%s/%s", repo.Reference.Registry, repo.Reference.Repository)); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// The pull itself needs no git, only the checkout.
	t.Setenv("PATH", t.TempDir())

	err = pull.Pull(repo.Reference.String(), pull.WithDir(t.TempDir()), pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fac"))
	if want := "switch to 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac: "; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Pull() error does not begin with %q, error: %v", want, err)
	}
	// rev-parse could not tell, so the error does not say the commit is not
	// there.
	if errors.Is(err, contains.ErrCommitNotFound) {
		t.Errorf("errors.Is matches Pull() error with contains.ErrCommitNotFound, error: %v", err)
	}
}

// TestPullWithBrokenGit checks that a tag that is there is not reported as
// not in the repository when git fails on the repository: with a config value
// it cannot read, as with a repository it does not trust, every git command
// exits with 128, rev-parse cannot tell, and the error of switch is returned
// as it is.
func TestPullWithBrokenGit(t *testing.T) {
	ts := httptest.NewTestServer(t, registry.New())

	originalTransport := http.DefaultTransport
	http.DefaultTransport = ts.Client().Transport
	t.Cleanup(func() {
		http.DefaultTransport = originalTransport
	})

	repo, err := remote.NewRepository("ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test")
	if err != nil {
		t.Fatalf("new repository: %v", err)
	}

	if err := setup(fmt.Sprintf("%s/%s", repo.Reference.Registry, repo.Reference.Repository)); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// The pull itself needs no git, only the checkout. util.Git keeps config
	// passed through the environment.
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.bare")
	t.Setenv("GIT_CONFIG_VALUE_0", "notabool")

	err = pull.Pull(repo.Reference.String(), pull.WithDir(t.TempDir()), pull.WithCheckout("v0.0.1"))
	if want := "switch to v0.0.1: "; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Pull() error does not begin with %q, error: %v", want, err)
	}
	if want := `stderr: "fatal: bad boolean config value 'notabool' for 'core.bare'`; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("Pull() error does not hold %q, error: %v", want, err)
	}
	if errors.Is(err, contains.ErrCommitNotFound) {
		t.Errorf("errors.Is matches Pull() error with contains.ErrCommitNotFound, error: %v", err)
	}
}

// TestMissing checks which targets missing takes to name nothing in the
// fixture: only those that git rev-parse says it cannot resolve, and not when
// git cannot tell. The fixture gets a second commit, whose hash begins with
// 9d3d as that of its commit does, so that 9d3d is an abbreviated hash that
// two commits begin with.
func TestMissing(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "fixtures", "vuls-data-raw-test.tar.zst"))
	if err != nil {
		t.Fatalf("open fixture. err: %v", err)
	}
	defer f.Close()

	dir := filepath.Join(t.TempDir(), "vuls-data-raw-test")
	if err := util.ExtractDotgitTarZst(f, dir); err != nil {
		t.Fatalf("extract fixture. err: %v", err)
	}

	bs, err := util.GitWithStdin(strings.NewReader("tree 403164dbcb94dfb2b004ce50fc619c1351bbd37e\nauthor t <t@example.com> 0 +0000\ncommitter t <t@example.com> 0 +0000\n\nambiguous 132403\n"), "-C", dir, "hash-object", "-t", "commit", "-w", "--stdin")
	if err != nil {
		t.Fatalf("write a commit. err: %v", err)
	}
	if got, want := string(bs), "9d3d6f888b6e6ad04b25d743994cef71313b26ad\n"; got != want {
		t.Fatalf("hash of the commit written. expected: %q, actual: %q", want, got)
	}

	tests := []struct {
		name   string
		target string
		// env is set for the case, to make git fail.
		env  map[string]string
		want bool
	}{
		{
			name:   "a commit",
			target: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
		},
		{
			name:   "a full hash of no object",
			target: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac",
			want:   true,
		},
		{
			name:   "a tag",
			target: "v0.0.1",
		},
		{
			name:   "a tag that is not there",
			target: "v0.0.2",
			want:   true,
		},
		{
			name:   "a branch that is not there",
			target: "develop",
			want:   true,
		},
		{
			// There, though not a commit.
			name:   "a tree",
			target: "v0.0.1^{tree}",
		},
		{
			// rev-parse exits with 1, as it cannot tell which of the two
			// commits 9d3d names.
			name:   "an abbreviated hash that two commits begin with",
			target: "9d3d",
		},
		{
			name:   "an abbreviated hash that two commits begin with, in capitals",
			target: "9D3D",
		},
		{
			name:   "an abbreviated hash that two commits begin with, followed by ~1",
			target: "9d3d~1",
		},
		{
			name:   "an abbreviated hash that two commits begin with, followed by ^{tree}",
			target: "9d3d^{tree}",
		},
		{
			name:   "describe output with an abbreviated hash that two commits begin with",
			target: "v0.0.1-1-g9d3d",
		},
		{
			// Only the commit of the fixture begins with 9d3d5, and it has
			// no parent.
			name:   "the parent of an abbreviated hash that one commit begins with, which has none",
			target: "9d3d5~1",
			want:   true,
		},
		{
			// A commit pinned by an abbreviated hash before the history was
			// truncated.
			name:   "an abbreviated hash that no object begins with",
			target: "ffff",
			want:   true,
		},
		{
			// git exits with 128 on a config value it cannot read, as it
			// does on a repository it does not trust.
			name:   "a tag that is not there, with a config value git cannot read",
			target: "v0.0.2",
			env:    map[string]string{"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.bare", "GIT_CONFIG_VALUE_0": "notabool"},
		},
		{
			name:   "a tag that is not there, without git",
			target: "v0.0.2",
			env:    map[string]string{"PATH": t.TempDir()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if got := pull.Missing(dir, tt.target); got != tt.want {
				t.Errorf("Missing(%q, %q). expected: %t, actual: %t", dir, tt.target, tt.want, got)
			}
		})
	}
}

// TestNotInRepository checks that errors.Is takes the error for a target that
// is not in the repository for contains.ErrCommitNotFound, and that otherwise
// it is the error of switch it wraps: its message after the one it adds, its
// chain, its cause for github.com/pkg/errors, and what %+v prints of it, with
// its stack trace.
func TestNotInRepository(t *testing.T) {
	cause := errors.New("exit status 128")
	switchErr := errors.Wrap(cause, "switch to v0.0.2")

	err := pull.NotInRepository(switchErr, "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test", "v0.0.2")
	if want := "v0.0.2 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten: switch to v0.0.2: exit status 128"; err.Error() != want {
		t.Errorf("Error(). expected: %q, actual: %q", want, err.Error())
	}
	if !errors.Is(err, contains.ErrCommitNotFound) {
		t.Errorf("errors.Is(%v, contains.ErrCommitNotFound) is false", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(%v, the cause of the error of switch) is false", err)
	}
	if errors.Cause(err) != cause {
		t.Errorf("errors.Cause(%v). expected: the cause of the error of switch, actual: %v", err, errors.Cause(err))
	}
	if got, want := fmt.Sprintf("%+v", err), fmt.Sprintf("%+v", switchErr); !strings.Contains(got, want) {
		t.Errorf("%%+v does not hold %%+v of the error of switch. expected to hold: %q, actual: %q", want, got)
	}
}

// TestPullCheckoutWorkers checks, from the argv git's trace2 records, that
// restore asks for a worker per CPU only when the git config does not say how
// many.
func TestPullCheckoutWorkers(t *testing.T) {
	tests := []struct {
		name    string
		workers string
		want    bool
	}{
		{
			name: "unset",
			want: true,
		},
		{
			name:    "set to 2",
			workers: "2",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, registry.New())

			originalTransport := http.DefaultTransport
			http.DefaultTransport = ts.Client().Transport
			t.Cleanup(func() {
				http.DefaultTransport = originalTransport
			})

			repo, err := remote.NewRepository("ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test")
			if err != nil {
				t.Fatalf("new repository: %v", err)
			}

			if err := setup(fmt.Sprintf("%s/%s", repo.Reference.Registry, repo.Reference.Repository)); err != nil {
				t.Fatalf("setup: %v", err)
			}

			// Keep the global and system config of the machine running the
			// test out of it.
			t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
			t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
			if tt.workers != "" {
				t.Setenv("GIT_CONFIG_COUNT", "1")
				t.Setenv("GIT_CONFIG_KEY_0", "checkout.workers")
				t.Setenv("GIT_CONFIG_VALUE_0", tt.workers)
			}
			trace := filepath.Join(t.TempDir(), "trace2.json")
			t.Setenv("GIT_TRACE2_EVENT", trace)

			if err := pull.Pull(repo.Reference.String(), pull.WithDir(t.TempDir()), pull.WithRestore(true)); err != nil {
				t.Fatalf("pull. err: %v", err)
			}

			f, err := os.Open(trace)
			if err != nil {
				t.Fatalf("open %s. err: %v", trace, err)
			}
			defer f.Close()

			var restores [][]string
			s := bufio.NewScanner(f)
			for s.Scan() {
				var e struct {
					Event string   `json:"event"`
					Argv  []string `json:"argv"`
				}
				if err := json.Unmarshal(s.Bytes(), &e); err != nil {
					t.Fatalf("unmarshal %q. err: %v", s.Text(), err)
				}
				if e.Event == "start" && slices.Contains(e.Argv, "restore") {
					restores = append(restores, e.Argv)
				}
			}
			if err := s.Err(); err != nil {
				t.Fatalf("scan %s. err: %v", trace, err)
			}

			if len(restores) != 1 {
				t.Fatalf("restore runs. expected: 1, actual: %q", restores)
			}
			if got := slices.Contains(restores[0], "checkout.workers=0"); got != tt.want {
				t.Errorf("checkout.workers=0 in %q. expected: %t, actual: %t", restores[0], tt.want, got)
			}
		})
	}
}

func setup(url string) error {
	ctx := context.TODO()

	repo, err := remote.NewRepository(url)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", url)
	}

	for _, f := range []struct {
		fixture string
		tags    []string
	}{
		{fixture: "vuls-data-raw-test", tags: []string{"vuls-data-raw-test", "vuls-data-raw-test-archive-1"}},
		// A repository whose HEAD deletes every file, which is the state a
		// fetch that wrote nothing back leaves behind.
		{fixture: "vuls-data-raw-test-emptied", tags: []string{"vuls-data-raw-test-emptied"}},
	} {
		bs, err := os.ReadFile(filepath.Join("testdata", "fixtures", fmt.Sprintf("%s.tar.zst", f.fixture)))
		if err != nil {
			return errors.Wrapf(err, "read %q", filepath.Join("testdata", "fixtures", fmt.Sprintf("%s.tar.zst", f.fixture)))
		}

		layerDescriptor, err := oras.PushBytes(ctx, repo, "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd", []byte(bs))
		if err != nil {
			return errors.Wrap(err, "push dotgit layer")
		}
		if layerDescriptor.Annotations == nil {
			layerDescriptor.Annotations = make(map[string]string)
		}
		if _, ok := layerDescriptor.Annotations[ocispec.AnnotationTitle]; !ok {
			layerDescriptor.Annotations[ocispec.AnnotationTitle] = fmt.Sprintf("%s.tar.zst", f.fixture)
		}

		desc, err := oras.PackManifest(ctx, repo, oras.PackManifestVersion1_1, "application/vnd.vulsio.vuls-data-db.dotgit+type", oras.PackManifestOptions{Layers: []ocispec.Descriptor{layerDescriptor}})
		if err != nil {
			return errors.Wrap(err, "pack manifest")
		}

		for _, tag := range f.tags {
			if err := repo.Tag(ctx, desc, tag); err != nil {
				return errors.Wrapf(err, "tagged %q for %+v", tag, desc)
			}
		}
	}

	return nil
}

// TestPull_retry breaks the download of the layer off after half of the blob,
// as the storage behind ghcr.io now and then does, and checks that Pull starts
// the download over.
func TestPull_retry(t *testing.T) {
	tests := []struct {
		name string
		// breaks is how many downloads of the layer break off before one goes
		// through.
		breaks int
		// beforeAnswer breaks the downloads off before the registry answers,
		// which fails the request rather than the body.
		beforeAnswer bool
		// corrupt answers the whole layer, but with zeros for its bytes, which
		// fails the extraction with no download breaking off.
		corrupt       bool
		wantDownloads int
		// archive is what the pulled tree has to equal, entry for entry and
		// byte for byte: the layer that was pushed. Nothing is checked out,
		// so that nothing but the extraction writes the tree.
		archive  string
		hasError bool
	}{
		{
			name:          "broken off once",
			breaks:        1,
			wantDownloads: 2,
			archive:       "testdata/fixtures/vuls-data-raw-test.tar.zst",
		},
		{
			name:          "broken off every time",
			breaks:        100,
			wantDownloads: 4,
			hasError:      true,
		},
		{
			name:          "request broken off once",
			breaks:        1,
			beforeAnswer:  true,
			wantDownloads: 2,
			archive:       "testdata/fixtures/vuls-data-raw-test.tar.zst",
		},
		{
			name:          "request broken off every time",
			breaks:        100,
			beforeAnswer:  true,
			wantDownloads: 4,
			hasError:      true,
		},
		{
			name:          "corrupt, which a retry does not change",
			corrupt:       true,
			wantDownloads: 1,
			hasError:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := registry.New()
			armed := false
			downloads := 0
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !armed || r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/blobs/") {
					reg.ServeHTTP(w, r)
					return
				}

				downloads++
				if !tt.corrupt && downloads > tt.breaks {
					reg.ServeHTTP(w, r)
					return
				}

				if tt.beforeAnswer {
					panic(http.ErrAbortHandler)
				}

				rec := httptest.NewRecorder()
				reg.ServeHTTP(rec, r)
				maps.Copy(w.Header(), rec.Header())
				w.WriteHeader(rec.Code)
				if tt.corrupt {
					// The client may hang up partway, as soon as the
					// decoder sees that the zeros are no archive.
					if _, err := w.Write(make([]byte, rec.Body.Len())); err != nil {
						t.Logf("write body: %v", err)
					}
					return
				}
				if _, err := w.Write(rec.Body.Bytes()[:rec.Body.Len()/2]); err != nil {
					t.Errorf("write body: %v", err)
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Errorf("flush: %v", err)
				}
				panic(http.ErrAbortHandler)
			}))

			// A connection of its own for every request, as net/http resends by
			// itself a request that fails on a reused connection before the
			// answer, which would take the place of the retry under test.
			tr, ok := ts.Client().Transport.(*http.Transport)
			if !ok {
				t.Fatalf("unexpected transport type. expected: %T, actual: %T", &http.Transport{}, ts.Client().Transport)
			}
			tr = tr.Clone()
			tr.DisableKeepAlives = true

			originalTransport := http.DefaultTransport
			http.DefaultTransport = tr
			t.Cleanup(func() {
				http.DefaultTransport = originalTransport
			})

			repo, err := remote.NewRepository("ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test")
			if err != nil {
				t.Fatalf("new repository: %v", err)
			}

			if err := setup(fmt.Sprintf("%s/%s", repo.Reference.Registry, repo.Reference.Repository)); err != nil {
				t.Fatalf("setup: %v", err)
			}
			armed = true

			dir := t.TempDir()
			err = pull.Pull(repo.Reference.String(), pull.WithDir(dir), pull.WithCheckout(""), pull.WithRetryWait(time.Millisecond))
			if downloads != tt.wantDownloads {
				t.Errorf("Pull() downloaded the layer %d times, want %d", downloads, tt.wantDownloads)
			}
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				got, err := treeEntries(filepath.Join(dir, "ghcr.io", "vulsio", "vuls-data-db"))
				if err != nil {
					t.Fatalf("read %s: %v", dir, err)
				}
				want, err := archiveEntries(tt.archive)
				if err != nil {
					t.Fatalf("read %s: %v", tt.archive, err)
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Pull(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

// entry is a directory, or a regular file and its content.
type entry struct {
	Dir     bool
	Content string
}

// treeEntries reads the tree under dir, keyed by the path relative to it.
func treeEntries(dir string) (map[string]entry, error) {
	es := make(map[string]entry)
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		p, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		switch {
		case p == ".":
		case d.IsDir():
			es[p] = entry{Dir: true}
		case d.Type().IsRegular():
			bs, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			es[p] = entry{Content: string(bs)}
		default:
			return errors.Errorf("unexpected file type. expected: %q, actual: %q", []string{"directory", "regular file"}, d.Type())
		}
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", dir)
	}
	return es, nil
}

// archiveEntries reads the entries of a tar.zst, keyed by their cleaned name.
func archiveEntries(archive string) (map[string]entry, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", archive)
	}
	defer f.Close()

	r, err := zstd.NewReader(f)
	if err != nil {
		return nil, errors.Wrap(err, "new zstd reader")
	}
	defer r.Close()

	es := make(map[string]entry)
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, "next tar reader")
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			es[filepath.Clean(hdr.Name)] = entry{Dir: true}
		case tar.TypeReg:
			bs, err := io.ReadAll(tr)
			if err != nil {
				return nil, errors.Wrapf(err, "read %s", hdr.Name)
			}
			es[filepath.Clean(hdr.Name)] = entry{Content: string(bs)}
		default:
			return nil, errors.Errorf("unexpected tar entry type. expected: %q, actual: %q", []byte{tar.TypeDir, tar.TypeReg}, hdr.Typeflag)
		}
	}
	return es, nil
}
