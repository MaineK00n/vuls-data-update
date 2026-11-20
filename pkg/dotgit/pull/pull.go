package pull

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/errcode"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	dir          string
	checkout     string
	restore      bool
	useNativeGit bool

	// retryWait is the wait before the first retry of a layer whose download
	// broke off, doubled for each one after. It is only ever changed by
	// WithRetryWait, which lives in export_test.go and is therefore absent from
	// the production build.
	retryWait time.Duration
}

// layerRetryMax is the number of retries of a layer whose download broke off.
const layerRetryMax = 3

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
		retryWait:    5 * time.Second,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	slog.Info("Pull dotgit", slog.String("repository", repository))

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
	if err := json.UnmarshalRead(r, &manifest); err != nil {
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

	if err := pullLayer(ctx, repo, *l, filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), options.retryWait); err != nil {
		return errors.Wrap(err, "pull layer")
	}

	if options.checkout != "" {
		if options.useNativeGit {
			if _, err := util.Git("-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "show-ref", "--verify", "--quiet", fmt.Sprintf("refs/heads/%s", options.checkout)); err != nil { // tag or commit
				if _, err := util.Git("-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "switch", "--detach", options.checkout); err != nil {
					return errors.Wrapf(err, "switch to %s", options.checkout)
				}
			} else { // branch
				if _, err := util.Git("-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "switch", options.checkout); err != nil {
					return errors.Wrapf(err, "switch to %s", options.checkout)
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
			// A repository whose every file has been deleted has nothing to
			// restore, and "git restore ." reads a pathspec that matches
			// nothing as fatal. Nothing to do is not a failure, and this is
			// the repository a pull most needs to survive: it is what a fetch
			// that wrote nothing back leaves behind, and putting the files
			// back is what the pull is for.
			bs, err := util.Git("-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "ls-files")
			if err != nil {
				return errors.Wrap(err, "list files")
			}

			if len(bs) > 0 {
				// git writes the files one at a time by default. Unless the
				// git config says how many, use a worker per CPU (git 2.32 or
				// later). config --get fails when checkout.workers is unset,
				// or when the config cannot be read, which restore will then
				// report itself.
				args := []string{"-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference)}
				if _, err := util.Git("-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "config", "--get", "checkout.workers"); err != nil {
					args = append(args, "-c", "checkout.workers=0")
				}
				if _, err := util.Git(append(args, "restore", ".")...); err != nil {
					return errors.Wrap(err, "restore worktree")
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

			if err := w.Reset(&git.ResetOptions{Mode: git.HardReset}); err != nil {
				return errors.Wrapf(err, "reset %s", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference))
			}
		}
	}

	return nil
}

// pullLayer fetches the layer and extracts it into dir.
//
// The layer is read straight into the extraction, so a connection that breaks
// off in the middle of the blob, as the storage behind ghcr.io now and then
// does with an HTTP/2 stream error or a connection reset, fails the extraction.
// The HTTP client of oras retries a request that fails, but not a body it has
// already handed over, nor a connection that fails for anything but a dial
// timeout. So a download that breaks off, of the body or of the request, is
// retried here from an emptied dir. What fails otherwise is not retried, as
// another download does not change it: an answer of the registry, such as a
// blob that is not there, and an error of the extraction itself, such as a full
// disk.
func pullLayer(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, dir string, wait time.Duration) error {
	for retry := 0; ; retry++ {
		retryable, err := func() (bool, error) {
			rc, err := repo.Fetch(ctx, desc)
			if err != nil {
				var errResp *errcode.ErrorResponse
				return !errors.As(err, &errResp) && !errors.Is(err, errdef.ErrNotFound) && ctx.Err() == nil, errors.Wrap(err, "fetch content")
			}
			defer rc.Close()

			r := &recordingReader{r: rc}
			if err := util.ExtractDotgitTarZst(r, dir); err != nil {
				return r.err() != nil, errors.Wrapf(err, "extract to %s", dir)
			}
			return false, nil
		}()
		if err == nil {
			return nil
		}
		if !retryable || retry >= layerRetryMax {
			return err
		}

		slog.Warn("Retry pulling the dotgit layer whose download broke off", slog.String("repository", repo.Reference.String()), slog.String("digest", desc.Digest.String()), slog.Int("retry", retry+1), slog.Duration("wait", wait), slog.String("err", err.Error()))

		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}

		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "wait to retry")
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// recordingReader records the first error, io.EOF aside, that reading r
// returned, which tells a download that broke off apart from an extraction that
// failed. The zstd decoder reads ahead in a goroutine of its own, hence the
// lock.
type recordingReader struct {
	r io.Reader

	mu      sync.Mutex
	readErr error
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && err != io.EOF {
		r.mu.Lock()
		if r.readErr == nil {
			r.readErr = err
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *recordingReader) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.readErr
}
