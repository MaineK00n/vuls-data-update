package grep

import (
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	treeish          string
	pathspecs        []string
	filesWithMatches bool
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

type filesWithMatchesOption bool

func (f filesWithMatchesOption) apply(opts *options) {
	opts.filesWithMatches = bool(f)
}

func WithFilesWithMatches(filesWithMatches bool) Option {
	return filesWithMatchesOption(filesWithMatches)
}

func Grep(repository string, patterns []string, opts ...Option) (string, error) {
	options := &options{
		treeish:          "main",
		pathspecs:        nil,
		filesWithMatches: false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	args := []string{"-C", repository, "grep", "--line-number"}
	if options.filesWithMatches {
		args = append(args, "--files-with-matches")
	}
	for _, pattern := range patterns {
		args = append(args, "-e", pattern)
	}
	args = append(args, options.treeish)
	if len(options.pathspecs) > 0 {
		args = append(args, "--")
		args = append(args, options.pathspecs...)
	}

	output, err := util.Git(args...)
	if err != nil {
		return "", errors.Wrap(err, "grep")
	}
	return string(output), nil
}
