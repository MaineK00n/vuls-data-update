package tree

import (
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	color     bool
	pathspecs []string
}

type Option interface {
	apply(*options)
}

type colorOption bool

func (c colorOption) apply(opts *options) {
	opts.color = bool(c)
}

func WithColor(c bool) Option {
	return colorOption(c)
}

type pathspecsOption []string

func (p pathspecsOption) apply(opts *options) {
	opts.pathspecs = []string(p)
}

func WithPathSpecs(pathspecs []string) Option {
	return pathspecsOption(pathspecs)
}

func Diff(repository, minus, plus string, opts ...Option) (string, error) {
	options := &options{
		color:     false,
		pathspecs: nil,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	args := []string{"-C", repository, "diff-tree", "-p"}
	if options.color {
		args = append(args, "--color")
	}
	args = append(args, minus, plus)
	if len(options.pathspecs) > 0 {
		args = append(args, "--")
		args = append(args, options.pathspecs...)
	}

	output, err := util.Git(args...)
	if err != nil {
		return "", errors.Wrap(err, "diff-tree")
	}
	return string(output), nil
}
