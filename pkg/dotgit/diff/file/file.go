package file

import (
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	color bool
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

func Diff(repository, minus, plus string, opts ...Option) (string, error) {
	options := &options{
		color: false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	args := []string{"-C", repository, "diff"}
	if options.color {
		args = append(args, "--color")
	}
	args = append(args, minus, plus)

	output, err := util.Git(args...)
	if err != nil {
		return "", errors.Wrap(err, "diff")
	}
	return string(output), nil
}
