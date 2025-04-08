package cat

import (
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
)

type options struct {
	treeish string
}

type Option interface {
	apply(*options)
}

type treeishOption string

func (t treeishOption) apply(opts *options) {
	opts.treeish = string(t)
}

func WithTreeish(id string) Option {
	return treeishOption(id)
}

func Cat(repository, path string, opts ...Option) (string, error) {
	options := &options{
		treeish: "main",
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return "", errors.Wrapf(err, "open %s", repository)
	}

	hash, err := r.ResolveRevision(plumbing.Revision(options.treeish))
	if err != nil {
		return "", errors.Wrapf(err, "resolve %s", options.treeish)
	}

	commit, err := r.CommitObject(*hash)
	if err != nil {
		return "", errors.Wrapf(err, "get commit %s", hash)
	}

	f, err := commit.File(path)
	if err != nil {
		return "", errors.Wrapf(err, "get file %s", path)
	}

	c, err := f.Contents()
	if err != nil {
		return "", errors.Wrapf(err, "get contents %s", path)
	}

	return c, nil
}
