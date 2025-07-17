package cat

import (
	"fmt"
	"os/exec"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
)

type options struct {
	useNativeGit bool
	treeish      string
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

type treeishOption string

func (t treeishOption) apply(opts *options) {
	opts.treeish = string(t)
}

func WithTreeish(id string) Option {
	return treeishOption(id)
}

func Cat(repository, path string, opts ...Option) (string, error) {
	options := &options{
		useNativeGit: true,
		treeish:      "main",
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.useNativeGit {
		cmd := exec.Command("git", "-C", repository, "show", fmt.Sprintf("%s:%s", options.treeish, path))
		output, err := cmd.Output()
		if err != nil {
			return "", errors.Wrapf(err, "exec %q", cmd.String())
		}
		return string(output), nil
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
