package cat

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
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

	output, err := util.Git("-C", repository, "show", fmt.Sprintf("%s:%s", options.treeish, path))
	if err != nil {
		return "", errors.Wrapf(err, "show %s:%s", options.treeish, path)
	}
	return string(output), nil
}
