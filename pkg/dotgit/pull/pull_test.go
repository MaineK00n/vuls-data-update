package pull_test

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
	}{
		{
			name: "vuls-data-raw-test restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test restore: false, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithRestore(false), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: main, restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: HEAD, restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("HEAD"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: v0.0.1, restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.1"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fab, restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: main, restore: false, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main"), pull.WithRestore(false), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: HEAD, restore: false, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("HEAD"), pull.WithRestore(false), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: v0.0.1, restore: false, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.1"), pull.WithRestore(false), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fab, restore: false, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"), pull.WithRestore(false), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test.tar.zst",
		},
		{
			name: "vuls-data-raw-test restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			name: "vuls-data-raw-test restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: main, restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main"), pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			// A fetch that writes nothing back leaves every file deleted, and
			// the pull that would put them back has to survive that state.
			name: "vuls-data-raw-test-emptied restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-emptied",
				opts:       []pull.Option{pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test-emptied.tar.zst",
		},
		{
			name: "vuls-data-raw-test-emptied restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-emptied",
				opts:       []pull.Option{pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test-emptied.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: main, restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main"), pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			// A commit behind the branch, as a lock file pins one: the
			// initial commit has the README.md that main deletes.
			name: "vuls-data-raw-test-emptied checkout: b9b8cec27035fddf3c7addcf7b76c8dda6be5e76, restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-emptied",
				opts:       []pull.Option{pull.WithCheckout("b9b8cec27035fddf3c7addcf7b76c8dda6be5e76"), pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			golden:    "testdata/golden/vuls-data-raw-test-emptied-b9b8cec-restored.tar.zst",
			wantHead:  "b9b8cec27035fddf3c7addcf7b76c8dda6be5e76",
			wantFiles: map[string]string{"README.md": "# vuls-data-raw-test\n"},
		},
		{
			name: "vuls-data-raw-test-emptied checkout: b9b8cec27035fddf3c7addcf7b76c8dda6be5e76, restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-emptied",
				opts:       []pull.Option{pull.WithCheckout("b9b8cec27035fddf3c7addcf7b76c8dda6be5e76"), pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			golden:    "testdata/golden/vuls-data-raw-test-emptied-b9b8cec-restored.tar.zst",
			wantHead:  "b9b8cec27035fddf3c7addcf7b76c8dda6be5e76",
			wantFiles: map[string]string{"README.md": "# vuls-data-raw-test\n"},
		},
		{
			// A name that switch accepts and cat-file -e does not, as with
			// "-" for the previous branch: the merge base of main and v0.0.1.
			name: "vuls-data-raw-test checkout: main...v0.0.1, restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main...v0.0.1"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			golden:   "testdata/golden/vuls-data-raw-test.tar.zst",
			wantHead: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
		},
		{
			// A valid tag name that go-git's revision parser rejects, which
			// is why go-git asks contains only after the tag lookup.
			name: "vuls-data-raw-test-at-tag checkout: v1@2, restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-at-tag",
				opts:       []pull.Option{pull.WithCheckout("v1@2"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			golden:   "testdata/golden/vuls-data-raw-test-at-tag.tar.zst",
			wantHead: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
		},
		{
			name: "vuls-data-raw-test-at-tag checkout: v1@2, restore: false, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-at-tag",
				opts:       []pull.Option{pull.WithCheckout("v1@2"), pull.WithRestore(false), pull.WithUseNativeGit(false)},
			},
			golden:   "testdata/golden/vuls-data-raw-test-at-tag.tar.zst",
			wantHead: "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
		},
		{
			// A target that is there but is not a commit: contains finds it,
			// so the error of switch is returned as it is.
			name: "vuls-data-raw-test checkout: v0.0.1^{tree}, restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.1^{tree}"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			hasError: true,
			wantErr:  "switch to v0.0.1^{tree}: ",
		},
		{
			// A commit pinned before vuls-data-db truncated the history is
			// no longer in the repository.
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac (not in the repository), restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fac"), pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			hasError: true,
			wantErr:  "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten: switch to 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac: ",
		},
		{
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac (not in the repository), restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fac"), pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			hasError: true,
			wantErr:  "get checkout options: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten: ",
		},
		{
			// go-git checks out the zero hash, which plumbing.NewHash makes
			// of v0.0.2, as master. Unless contains is asked before the
			// checkout, the pull succeeds on master.
			name: "vuls-data-raw-test-master checkout: v0.0.2 (not in the repository), restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-master",
				opts:       []pull.Option{pull.WithCheckout("v0.0.2"), pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			hasError: true,
			wantErr:  "v0.0.2 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-master, whose history may have been truncated or rewritten: switch to v0.0.2: ",
		},
		{
			name: "vuls-data-raw-test-master checkout: v0.0.2 (not in the repository), restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-master",
				opts:       []pull.Option{pull.WithCheckout("v0.0.2"), pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			hasError: true,
			wantErr:  "get checkout options: v0.0.2 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-master, whose history may have been truncated or rewritten: ",
		},
		{
			// contains reads a name as cat-file -e does, so it cannot tell
			// whether the target of a name that switch reads otherwise is
			// there, and the error of switch is returned as it is.
			name: "vuls-data-raw-test checkout: - (no previous branch), restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("-"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			hasError: true,
			wantErr:  "switch to -: ",
		},
		{
			name: "vuls-data-raw-test checkout: main...v0.0.2 (no v0.0.2), restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("main...v0.0.2"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			hasError: true,
			wantErr:  "switch to main...v0.0.2: ",
		},
		{
			// A valid tag name that is not there, and that go-git's revision
			// parser rejects.
			name: "vuls-data-raw-test checkout: v9@9 (not in the repository), restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v9@9"), pull.WithRestore(false), pull.WithUseNativeGit(true)},
			},
			hasError: true,
			wantErr:  "v9@9 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten: switch to v9@9: ",
		},
		{
			name: "vuls-data-raw-test checkout: v9@9 (not in the repository), restore: false, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v9@9"), pull.WithRestore(false), pull.WithUseNativeGit(false)},
			},
			hasError: true,
			wantErr:  "get checkout options: v9@9 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten: ",
		},
		{
			name: "vuls-data-raw-test-archive-1 restore: false, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test-archive-1",
				opts:       []pull.Option{pull.WithRestore(false), pull.WithUseNativeGit(true)},
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

// TestPullWithoutGit checks that a target native git cannot be run to check
// out is not reported as not in the repository: contains cannot tell, so the
// error of switch is returned as it is.
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

	err = pull.Pull(repo.Reference.String(), pull.WithDir(t.TempDir()), pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fac"), pull.WithUseNativeGit(true))
	if want := "switch to 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac: "; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Pull() error does not begin with %q, error: %v", want, err)
	}
}

// TestNotFound checks which errors of contains notFound takes to say that the
// target is not in the repository, and which to say that the check could not
// be made. The errors, and so the exit statuses of git, come from contains on
// the fixture where they can.
func TestNotFound(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "fixtures", "vuls-data-raw-test.tar.zst"))
	if err != nil {
		t.Fatalf("open fixture. err: %v", err)
	}
	defer f.Close()

	dir := filepath.Join(t.TempDir(), "vuls-data-raw-test")
	if err := util.ExtractDotgitTarZst(f, dir); err != nil {
		t.Fatalf("extract fixture. err: %v", err)
	}

	tests := []struct {
		name         string
		err          error
		useNativeGit bool
		want         bool
	}{
		{
			name:         "no error, native git",
			err:          contains.Contains(dir, "v0.0.1", contains.WithUseNativeGit(true)),
			useNativeGit: true,
		},
		{
			name: "no error, go-git",
			err:  contains.Contains(dir, "v0.0.1", contains.WithUseNativeGit(false)),
		},
		{
			name:         "exit status 1, a hash cat-file -e does not have, native git",
			err:          contains.Contains(dir, "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac", contains.WithUseNativeGit(true)),
			useNativeGit: true,
			want:         true,
		},
		{
			name:         "exit status 128, a name cat-file -e cannot resolve, native git",
			err:          contains.Contains(dir, "v0.0.2", contains.WithUseNativeGit(true)),
			useNativeGit: true,
			want:         true,
		},
		{
			name:         "exit status 129, an option cat-file -e does not know, native git",
			err:          contains.Contains(dir, "-b", contains.WithUseNativeGit(true)),
			useNativeGit: true,
		},
		{
			// What os/exec returns when git is not on PATH. TestPullWithoutGit
			// brings it about through Pull.
			name:         "git cannot be run, native git",
			err:          errors.Wrap(&exec.Error{Name: "git", Err: exec.ErrNotFound}, "check 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac exists"),
			useNativeGit: true,
		},
		{
			name: "reference not found, go-git",
			err:  contains.Contains(dir, "v0.0.2", contains.WithUseNativeGit(false)),
			want: true,
		},
		{
			name: "a name the revision parser rejects, go-git",
			err:  contains.Contains(dir, "v9@9", contains.WithUseNativeGit(false)),
			want: true,
		},
		{
			name: "repository does not exist, go-git",
			err:  contains.Contains(t.TempDir(), "v0.0.1", contains.WithUseNativeGit(false)),
		},
		{
			name: "repository cannot be read, go-git",
			err:  errors.Wrap(&fs.PathError{Op: "open", Path: filepath.Join(dir, ".git"), Err: fs.ErrPermission}, "open vuls-data-raw-test"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pull.NotFound(tt.err, tt.useNativeGit); got != tt.want {
				t.Errorf("NotFound(%v, %t). expected: %t, actual: %t", tt.err, tt.useNativeGit, tt.want, got)
			}
		})
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

			if err := pull.Pull(repo.Reference.String(), pull.WithDir(t.TempDir()), pull.WithRestore(true), pull.WithUseNativeGit(true)); err != nil {
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
		// vuls-data-raw-test with a master branch, which go-git checks out
		// for the zero hash.
		{fixture: "vuls-data-raw-test-master", tags: []string{"vuls-data-raw-test-master"}},
		// vuls-data-raw-test with a tag, v1@2, whose name go-git's revision
		// parser rejects.
		{fixture: "vuls-data-raw-test-at-tag", tags: []string{"vuls-data-raw-test-at-tag"}},
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
