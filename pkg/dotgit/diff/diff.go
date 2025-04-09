package diff

import (
	"bytes"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gitdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
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

	r, err := git.PlainOpen(repository)
	if err != nil {
		return "", errors.Wrapf(err, "open %s", repository)
	}

	treeish, path, ok := strings.Cut(minus, ":")
	if !ok {
		return "", errors.Errorf("unexpected diff minus file format. expected: %q, actual: %q", "<treeish>:<path>", minus)
	}

	from, err := getChangeEntry(r, path, treeish)
	if err != nil {
		return "", errors.Wrapf(err, "get change entry %s:%s", treeish, path)
	}

	treeish, path, ok = strings.Cut(plus, ":")
	if !ok {
		return "", errors.Errorf("unexpected diff plus file format. expected: %q, actual: %q", "<treeish>:<path>", minus)
	}

	to, err := getChangeEntry(r, path, treeish)
	if err != nil {
		return "", errors.Wrapf(err, "get change entry %s:%s", treeish, path)
	}

	patch, err := (&object.Change{
		From: from,
		To:   to,
	}).Patch()
	if err != nil {
		return "", errors.Wrap(err, "get patch")
	}

	buf := bytes.NewBuffer(nil)
	ue := gitdiff.NewUnifiedEncoder(buf, gitdiff.DefaultContextLines)
	if options.color {
		ue.SetColor(gitdiff.NewColorConfig())
	}
	if err := ue.Encode(patch); err != nil {
		return "", errors.Wrap(err, "encode patch")
	}

	return buf.String(), nil
}

func getChangeEntry(repository *git.Repository, path, treeish string) (object.ChangeEntry, error) {
	hash, err := repository.ResolveRevision(plumbing.Revision(treeish))
	if err != nil {
		return object.ChangeEntry{}, errors.Wrapf(err, "resolve %s", treeish)
	}

	commit, err := repository.CommitObject(*hash)
	if err != nil {
		return object.ChangeEntry{}, errors.Wrapf(err, "get commit %s", hash)
	}

	tree, err := commit.Tree()
	if err != nil {
		return object.ChangeEntry{}, errors.Wrapf(err, "get tree %s", commit.Hash)
	}

	entry, err := tree.FindEntry(path)
	if err != nil {
		return object.ChangeEntry{}, errors.Wrapf(err, "find entry %s", path)
	}

	return object.ChangeEntry{
		Name:      path,
		Tree:      tree,
		TreeEntry: *entry,
	}, nil
}
