package pull_test

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/pull"
)

func TestPull(t *testing.T) {
	type args struct {
		repository string
		opts       []pull.Option
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		hasError bool
		wantErr  string
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
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fab, restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"), pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
		},
		{
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fab, restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fab"), pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			golden: "testdata/golden/vuls-data-raw-test-restored.tar.zst",
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
			wantErr:  "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten",
		},
		{
			name: "vuls-data-raw-test checkout: 9d3d5d486d4c9414321a2df56f2e007c4c2c8fac (not in the repository), restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("9d3d5d486d4c9414321a2df56f2e007c4c2c8fac"), pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			hasError: true,
			wantErr:  "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten",
		},
		{
			name: "vuls-data-raw-test checkout: v0.0.2 (not in the repository), restore: true, native git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.2"), pull.WithRestore(true), pull.WithUseNativeGit(true)},
			},
			hasError: true,
			wantErr:  "v0.0.2 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten",
		},
		{
			name: "vuls-data-raw-test checkout: v0.0.2 (not in the repository), restore: true, go-git",
			args: args{
				repository: "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test",
				opts:       []pull.Option{pull.WithCheckout("v0.0.2"), pull.WithRestore(true), pull.WithUseNativeGit(false)},
			},
			hasError: true,
			wantErr:  "v0.0.2 is not in ghcr.io/vulsio/vuls-data-db:vuls-data-raw-test, whose history may have been truncated or rewritten",
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
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Pull() error does not contain %q, error: %v", tt.wantErr, err)
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
