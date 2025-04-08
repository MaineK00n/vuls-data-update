package grep

import (
	"regexp"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
)

type options struct {
	treeish   string
	pathspecs []string
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

type pathspecsOption []string

func (p pathspecsOption) apply(opts *options) {
	opts.pathspecs = []string(p)
}

func WithPathSpecs(pathspecs []string) Option {
	return pathspecsOption(pathspecs)
}

func Grep(repository string, patterns []string, opts ...Option) ([]git.GrepResult, error) {
	options := &options{
		treeish:   "main",
		pathspecs: nil,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", repository)
	}

	hash, err := r.ResolveRevision(plumbing.Revision(options.treeish))
	if err != nil {
		return nil, errors.Wrapf(err, "resolve %s", options.treeish)
	}

	rePatterns := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, errors.Wrapf(err, "compile %q", pattern)
		}
		rePatterns = append(rePatterns, re)
	}

	rePathSpecs := make([]*regexp.Regexp, 0, len(options.pathspecs))
	for _, pathspec := range options.pathspecs {
		re, err := regexp.Compile(pathspec)
		if err != nil {
			return nil, errors.Wrapf(err, "compile %q", pathspec)
		}
		rePathSpecs = append(rePathSpecs, re)
	}

	rs, err := r.Grep(&git.GrepOptions{
		CommitHash: *hash,
		Patterns:   rePatterns,
		PathSpecs:  rePathSpecs,
	})
	if err != nil {
		return nil, errors.Wrap(err, "grep")
	}

	return rs, nil
}
