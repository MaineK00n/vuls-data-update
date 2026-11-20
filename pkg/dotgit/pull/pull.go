package pull

import (
	"context"
	"encoding/json/v2"
	stderrors "errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/storer"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/contains"
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
			if _, err := util.Git("-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "show-ref", "--verify", "--quiet", fmt.Sprintf("refs/heads/%s", options.checkout)); err != nil { // tag or commit
				if _, err := util.Git("-C", filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), "switch", "--detach", options.checkout); err != nil {
					// switch reports a commit that is not in the repository
					// as "unable to read tree", which reads like corruption,
					// so if contains finds that the target is not there
					// either, say so in front of the error of switch. Asking
					// only after a failure lets every name switch accepts
					// reach it as before. contains reads a name as cat-file
					// -e does, so it is not asked about a name that switch
					// reads otherwise: one that begins with "-", the previous
					// branch or an option, or A...B, the merge base of A and
					// B. For those, and when contains cannot tell, as when
					// git cannot be run, the error of switch, which says how
					// it failed, is returned as it is.
					if !strings.HasPrefix(options.checkout, "-") && !strings.Contains(options.checkout, "...") {
						if err2 := contains.Contains(filepath.Join(options.dir, repo.Reference.Registry, repo.Reference.Repository, repo.Reference.Reference), options.checkout, contains.WithUseNativeGit(true)); notFound(err2, true) {
							return notInRepository(errors.Wrapf(err, "switch to %s", options.checkout), repository, options.checkout)
						}
					}
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

				// Neither a branch nor a tag. Native git looks a name up as a
				// ref before anything else, by git's rules: as it is, such as
				// refs/heads/main or ORIG_HEAD, under refs/, such as heads/main
				// or g for refs/g, and as a remote-tracking branch. So does
				// go-git here, so that no ref is refused or reported missing
				// for what its name looks like, such as
				// refs/heads/release-gdead, and outside go-git's revision
				// parser, which rejects a ref such as refs/tags/v1@2. go-git
				// reads a name as it is only if it is under refs/ or made of
				// upper case letters and "_".
				//
				// go-git checks out the commit found, not plumbing.NewHash of
				// the name, which makes the zero hash of any name but a full
				// hash, and go-git checks out the zero hash as master.
				for _, rule := range plumbing.RefRevParseRules {
					name := plumbing.ReferenceName(fmt.Sprintf(rule, options.checkout))
					if !name.IsSafe() {
						continue
					}
					ref, err := storer.ResolveReference(r.Storer, name)
					if errors.Is(err, plumbing.ErrReferenceNotFound) {
						continue
					}
					if err != nil {
						return git.CheckoutOptions{}, errors.Wrapf(err, "get %q as ref", name)
					}
					// The commit the ref points to, through a tag. A file of
					// the repository that go-git reads as a ref, such as
					// COMMIT_EDITMSG, points to none, and git does not read it
					// as a ref, so the next rule is tried.
					h, err := r.ResolveRevision(plumbing.Revision(ref.Hash().String()))
					if err != nil {
						if notFound(err, false) {
							continue
						}
						return git.CheckoutOptions{}, errors.Wrapf(err, "get %q as commit", name)
					}
					return git.CheckoutOptions{Hash: *h, Keep: true}, nil
				}

				// No ref has the name. A name for which ResolveRevision may
				// find another commit than native git is refused. One is an
				// expression, as ResolveRevision skips parts of some, such as
				// ^{tree}: a ref name can hold none of "~", "^", ":", "@{" or
				// "..", nor be "@", which is HEAD.
				if strings.ContainsAny(options.checkout, "~^:") || strings.Contains(options.checkout, "@{") || strings.Contains(options.checkout, "..") || options.checkout == "@" {
					return git.CheckoutOptions{}, errors.Errorf("go-git checks out no expression, such as %q, use native git", options.checkout)
				}

				// Another is an abbreviated hash: of the commits it matches,
				// ResolveRevision takes the first, where native git refuses one
				// that matches more than one. To find them, it goes through the
				// hash of every packed object.
				if abbreviated(options.checkout) {
					return git.CheckoutOptions{}, errors.Errorf("go-git checks out no abbreviated hash, such as %q, use native git", options.checkout)
				}

				// git reads any other name but a full hash only as a ref, so
				// it is not there. Not asking ResolveRevision about it also
				// keeps it from reading one such as 9d3 or 0000g as an
				// abbreviated hash, which git does not, and from going through
				// the hash of every packed object to find it.
				if !plumbing.IsHash(options.checkout) {
					return git.CheckoutOptions{}, notInRepository(errors.Wrapf(plumbing.ErrReferenceNotFound, "get %q as ref", options.checkout), repository, options.checkout)
				}

				// A full hash, resolved in the repository opened above, not
				// through contains, which would open it again and load every
				// pack index a second time.
				h, err := r.ResolveRevision(plumbing.Revision(options.checkout))
				if err != nil {
					err = errors.Wrapf(err, "resolve %s", options.checkout)
					if notFound(err, false) {
						return git.CheckoutOptions{}, notInRepository(err, repository, options.checkout)
					}
					return git.CheckoutOptions{}, errors.Wrapf(err, "get %q as commit", options.checkout)
				}

				return git.CheckoutOptions{Hash: *h, Keep: true}, nil
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

// notInRepository wraps err for a checkout target, a tag or a commit, that is
// not in the dotgit pulled from repository: the error of switch on the native
// path, and on the go-git path, where the target is looked up before the
// checkout, that of ResolveRevision for a full hash, and for any other name,
// that it is no ref. vuls-data-db keeps only the last
// commits of a dotgit's history, so a commit pinned before it truncated the
// history is gone from a repository that is otherwise fine.
func notInRepository(err error, repository, checkout string) error {
	return errors.Wrapf(err, "%s is not in %s, whose history may have been truncated or rewritten", checkout, repository)
}

// notFound reports whether err says that the target is not in the repository,
// rather than that the check could not be made. err is from contains on native
// git, and from ResolveRevision on go-git.
//
// Native git: git cat-file -e exits with 1 for a hash it does not have, and
// with 128 for a name it cannot resolve. 128 is also how it ends on other fatal
// errors, but contains is asked only after switch has failed, and the error of
// switch, which follows the message, says which. Without an exit status, git
// could not be run.
//
// go-git: ResolveRevision is asked only about a full hash, the target's or the
// one a ref points to, in the repository Pull has already opened. It answers
// plumbing.ErrReferenceNotFound for an object that is neither a commit nor a
// tag, or that it cannot read, and its other errors, such as for a tag whose
// commit is not there, also leave nothing to check out. Only an
// *fs.PathError, from a file of the repository that cannot be read, says that
// the check could not be made.
func notFound(err error, useNativeGit bool) bool {
	if err == nil {
		return false
	}
	if useNativeGit {
		ee, ok := stderrors.AsType[*exec.ExitError](err)
		return ok && (ee.ExitCode() == 1 || ee.ExitCode() == 128)
	}
	_, ok := stderrors.AsType[*fs.PathError](err)
	return !ok
}

// abbreviated reports whether git reads name as an abbreviated hash: a name of
// four to thirty-nine hex characters, or four or more of them after the last
// "-g" of a name, as in v1.0-2-g9d3d5d4, which git describe writes.
func abbreviated(name string) bool {
	if len(name) >= 4 && len(name) < 40 && isHex(name) {
		return true
	}
	i := strings.LastIndex(name, "-g")
	return i >= 0 && len(name)-(i+2) >= 4 && isHex(name[i+2:])
}

// isHex reports whether s holds nothing but hex digits, which "" does.
func isHex(s string) bool {
	return strings.TrimLeft(s, "0123456789abcdefABCDEF") == ""
}
