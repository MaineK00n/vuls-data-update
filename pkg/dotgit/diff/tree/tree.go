package tree

import (
	"bytes"
	"os/exec"
	"regexp"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
)

type options struct {
	useNativeGit bool
	color        bool
	pathspecs    []string
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
		useNativeGit: true,
		color:        false,
		pathspecs:    nil,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.useNativeGit {
		args := []string{"-C", repository, "diff-tree", "-p"}
		if options.color {
			args = append(args, "--color")
		}
		args = append(args, minus, plus)
		if len(options.pathspecs) > 0 {
			args = append(args, "--")
			args = append(args, options.pathspecs...)
		}

		cmd := exec.Command("git", args...)
		output, err := cmd.Output()
		if err != nil {
			return "", errors.Wrapf(err, "exec %q", cmd.String())
		}
		return string(output), nil
	}

	rePathSpecs := make([]*regexp.Regexp, 0, len(options.pathspecs))
	for _, pathspec := range options.pathspecs {
		re, err := regexp.Compile(pathspec)
		if err != nil {
			return "", errors.Wrapf(err, "compile %q", pathspec)
		}
		rePathSpecs = append(rePathSpecs, re)
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return "", errors.Wrapf(err, "open %s", repository)
	}

	f := func(treeish string) (*object.Tree, error) {
		hash, err := r.ResolveRevision(plumbing.Revision(treeish))
		if err != nil {
			return nil, errors.Wrapf(err, "resolve %q", treeish)
		}

		commit, err := r.CommitObject(*hash)
		if err != nil {
			return nil, errors.Wrapf(err, "get commit object for %q", *hash)
		}

		tree, err := commit.Tree()
		if err != nil {
			return nil, errors.Wrap(err, "get tree for commit object")
		}

		return tree, nil
	}

	minusTree, err := f(minus)
	if err != nil {
		return "", errors.Wrap(err, "get tree")
	}
	plusTree, err := f(plus)
	if err != nil {
		return "", errors.Wrap(err, "get tree")
	}

	changes, err := minusTree.Diff(plusTree)
	if err != nil {
		return "", errors.Wrapf(err, "get changes between %q and %q", minus, plus)
	}

	var cs object.Changes
	if len(rePathSpecs) > 0 {
		for _, change := range changes {
			if change == nil {
				return "", errors.New("nil change found in changes")
			}
			for _, re := range rePathSpecs {
				if re.MatchString(change.From.Name) || re.MatchString(change.To.Name) {
					cs = append(cs, change)
					break
				}
			}
		}
	} else {
		cs = changes
	}

	p, err := cs.Patch()
	if err != nil {
		return "", errors.Wrap(err, "get patch for changes")
	}

	buf := bytes.NewBuffer(nil)
	ue := diff.NewUnifiedEncoder(buf, diff.DefaultContextLines)
	if options.color {
		ue.SetColor(diff.NewColorConfig())
	}
	if err := ue.Encode(p); err != nil {
		return "", errors.Wrap(err, "encode patch")
	}

	return buf.String(), nil
}
