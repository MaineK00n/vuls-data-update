package pull

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	dir          string
	checkout     string
	restore      bool
	useNativeGit bool
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type checkoutOption string

func (c checkoutOption) apply(opts *options) {
	opts.checkout = string(c)
}

func WithCheckout(checkout string) Option {
	return checkoutOption(checkout)
}

type restoreOption bool

func (r restoreOption) apply(opts *options) {
	opts.restore = bool(r)
}

func WithRestore(restore bool) Option {
	return restoreOption(restore)
}

type useNativeGitOption bool

func (o useNativeGitOption) apply(opts *options) {
	opts.useNativeGit = bool(o)
}

func WithUseNativeGit(native bool) Option {
	return useNativeGitOption(native)
}

func Pull(repository string, opts ...Option) error {
	options := &options{
		dir:          filepath.Join(util.CacheDir(), "dotgit"),
		checkout:     "main",
		restore:      false,
		useNativeGit: true,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	log.Printf("[INFO] Pull dotgit from %s", repository)

	ctx := context.TODO()

	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference == "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, repository)
	}

	if err := os.RemoveAll(filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference)); err != nil {
		return errors.Wrapf(err, "remove %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
	}

	_, r, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		return errors.Wrap(err, "fetch manifest")
	}
	defer r.Close()

	var manifest ocispec.Manifest
	if err := json.NewDecoder(r).Decode(&manifest); err != nil {
		return errors.Wrap(err, "decode manifest")
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd" {
				return &l
			}
		}
		return nil
	}()
	if l == nil {
		return errors.Errorf("not found digest and filename from layers, actual layers: %#v", manifest.Layers)
	}

	r, err = repo.Fetch(ctx, *l)
	if err != nil {
		return errors.Wrap(err, "fetch content")
	}
	defer r.Close()

	if err := util.ExtractDotgitTarZst(r, filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference)); err != nil {
		return errors.Wrapf(err, "extract to %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
	}

	if options.checkout != "" {
		if options.useNativeGit {
			cmd := exec.Command("git", "-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "show-ref", "--verify", "--quiet", fmt.Sprintf("refs/heads/%s", options.checkout))
			if err := cmd.Run(); err != nil { // tag or commit
				cmd := exec.Command("git", "-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "switch", "--detach", options.checkout)
				if err := cmd.Run(); err != nil {
					return errors.Wrapf(err, "exec %q", cmd.String())
				}
			} else { // branch
				cmd := exec.Command("git", "-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "switch", options.checkout)
				if err := cmd.Run(); err != nil {
					return errors.Wrapf(err, "exec %q", cmd.String())
				}
			}
		} else {
			r, err := git.PlainOpen(filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			}

			w, err := r.Worktree()
			if err != nil {
				return errors.Wrapf(err, "git worktree %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			}

			o, err := func() (git.CheckoutOptions, error) {
				if options.checkout == "HEAD" {
					ref, err := r.Head()
					if err != nil {
						return git.CheckoutOptions{}, errors.Wrap(err, "get HEAD")
					}
					return git.CheckoutOptions{Hash: ref.Hash(), Keep: true}, nil
				}

				ref, err := r.Reference(plumbing.NewBranchReferenceName(options.checkout), false)
				if err != nil && !errors.Is(err, plumbing.ErrReferenceNotFound) {
					return git.CheckoutOptions{}, errors.Wrapf(err, "get %q as branch", options.checkout)
				}
				if err == nil {
					return git.CheckoutOptions{Branch: ref.Name(), Keep: true}, nil
				}

				ref, err = r.Reference(plumbing.NewTagReferenceName(options.checkout), false)
				if err != nil && !errors.Is(err, plumbing.ErrReferenceNotFound) {
					return git.CheckoutOptions{}, errors.Wrapf(err, "get %q as tag", options.checkout)
				}
				if err == nil {
					return git.CheckoutOptions{Hash: ref.Hash(), Keep: true}, nil
				}

				return git.CheckoutOptions{Hash: plumbing.NewHash(options.checkout), Keep: true}, nil
			}()
			if err != nil {
				return errors.Wrap(err, "get checkout options")
			}

			if err := w.Checkout(&o); err != nil {
				return errors.Wrapf(err, "checkout %s", options.checkout)
			}
		}
	}

	if options.restore {
		if options.useNativeGit {
			cmd := exec.Command("git", "-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "restore", ".")
			if err := cmd.Run(); err != nil {
				return errors.Wrapf(err, "exec %q", cmd.String())
			}
		} else {
			r, err := git.PlainOpen(filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			if err != nil {
				return errors.Wrapf(err, "open %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			}

			w, err := r.Worktree()
			if err != nil {
				return errors.Wrapf(err, "git worktree %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			}

			if err := w.Reset(&git.ResetOptions{Mode: git.HardReset}); err != nil {
				return errors.Wrapf(err, "reset %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			}
		}
	}

	return nil
}
