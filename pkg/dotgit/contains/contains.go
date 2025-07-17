package contains

import (
	"fmt"
	"os/exec"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
)

type options struct {
	useNativeGit bool
}

type Option interface {
	apply(*options)
}

type useNativeGitOption bool

func (o useNativeGitOption) apply(opts *options) {
	opts.useNativeGit = bool(o)
}

func WithUseNativeGit(native bool) Option {
	return useNativeGitOption(native)
}

type CommitNotFoundError struct {
	Repository string
	Commit     string
	Err        error
}

func (e *CommitNotFoundError) Error() string {
	return fmt.Sprintf("commit %s not found in %s: %v", e.Commit, e.Repository, e.Err)
}

func (e *CommitNotFoundError) Unwrap() error { return e.Err }

func Contains(repository, commit string, opts ...Option) error {
	options := &options{
		useNativeGit: true,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.useNativeGit {
		cmd := exec.Command("git", "-C", repository, "cat-file", "-e", commit)
		if err := cmd.Run(); err != nil {
			return errors.Wrapf(err, "exec %q", cmd.String())
		}
		return nil
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return errors.Wrapf(err, "open %s", repository)
	}

	hash, err := r.ResolveRevision(plumbing.Revision(commit))
	if err != nil {
		return errors.Wrapf(err, "resolve %s", commit)
	}

	if _, err := r.CommitObject(*hash); err != nil {
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			return &CommitNotFoundError{
				Repository: repository,
				Commit:     commit,
				Err:        err,
			}
		}
		return errors.Wrap(err, "get commit")
	}

	return nil
}
