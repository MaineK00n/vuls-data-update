package contains

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
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

func Contains(repository, commit string, opts ...Option) error {
	options := &options{
		useNativeGit: true,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.useNativeGit {
		if _, err := util.Git("-C", repository, "cat-file", "-e", commit); err != nil {
			return errors.Wrap(err, "git cat-file")
		}
		return nil
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return errors.Wrapf(err, "open %s", repository)
	}

	if _, err := r.ResolveRevision(plumbing.Revision(commit)); err != nil {
		return errors.Wrapf(err, "resolve %s", commit)
	}

	return nil
}
