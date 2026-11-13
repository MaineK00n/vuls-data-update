package contains

import (
	stderrors "errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

var (
	// ErrBranchNotFound is the cause of the error Contains returns with
	// WithBranch when the repository has no such branch.
	ErrBranchNotFound = errors.New("branch not found")

	// ErrCommitNotFound is the cause of the error Contains returns with
	// WithBranch when commit is not the full hash of a commit in the
	// repository.
	ErrCommitNotFound = errors.New("commit not found")

	// ErrNotReachable is the cause of the error Contains returns with
	// WithBranch when the commit is neither the tip of the branch nor an
	// ancestor of it.
	ErrNotReachable = errors.New("commit not reachable from branch")
)

type options struct {
	useNativeGit bool
	branch       string
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

type branchOption string

func (b branchOption) apply(opts *options) {
	opts.branch = string(b)
}

// WithBranch makes Contains also check that the commit, given as its full
// hash, is on branch, a branch name such as "main". An empty branch, the
// default, checks only that the object exists.
func WithBranch(branch string) Option {
	return branchOption(branch)
}

// Contains checks that repository has commit.
//
// By default, commit is any name of an object, and Contains checks only that
// the object exists.
//
// With WithBranch, Contains checks, in this order, that
//  1. commit resolves to a commit, and is that commit's own full hash, in
//     either case: not an abbreviation, a ref name, or an annotated tag's hash;
//  2. the branch refs/heads/<branch> exists, matched exactly;
//  3. the commit is the tip of the branch or an ancestor of it.
//
// The error of the first check that fails wraps ErrCommitNotFound,
// ErrBranchNotFound or ErrNotReachable. A branch that is not a valid branch
// name, which could read as a revision in refs/heads/<branch>, is an error
// that wraps none of them. So is a failure to run a check, which holds git's
// stderr.
func Contains(repository, commit string, opts ...Option) error {
	options := &options{
		useNativeGit: true,
		branch:       "",
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.branch != "" {
		if err := plumbing.NewBranchReferenceName(options.branch).Validate(); err != nil {
			return errors.Wrapf(err, "validate branch %q", options.branch)
		}
	}

	if options.useNativeGit {
		return containsNativeGit(repository, commit, options.branch)
	}
	return containsGoGit(repository, commit, options.branch)
}

func containsNativeGit(repository, commit, branch string) error {
	if branch == "" {
		if _, err := util.Git("-C", repository, "cat-file", "-e", commit); err != nil {
			return errors.Wrapf(err, "check %s exists", commit)
		}
		return nil
	}

	// rev-parse --verify --quiet exits 1 when the name does not resolve to a
	// commit: missing, or an object of another type. ^{commit} makes it read
	// the object; given a full hash alone, it prints the hash without looking
	// the object up.
	bs, err := util.Git("-C", repository, "rev-parse", "--verify", "--quiet", "--end-of-options", fmt.Sprintf("%s^{commit}", commit))
	if err != nil {
		if exitedWith(err, 1) {
			return errors.Wrapf(ErrCommitNotFound, "resolve %s (the history may have been truncated or rewritten)", commit)
		}
		return errors.Wrapf(err, "resolve %s", commit)
	}
	hash := strings.TrimSpace(string(bs))
	if err := checkFullHash(commit, hash); err != nil {
		return err
	}

	// for-each-ref matches ref names, and lists the ref only if it contains
	// the commit. merge-base --is-ancestor <hash> refs/heads/<branch> would
	// read a missing branch as a revision: a tag named refs/heads/<branch>,
	// or a name like describe output (x-1-g<hash>) as that commit.
	ref := fmt.Sprintf("refs/heads/%s", branch)
	bs, err = util.Git("-C", repository, "for-each-ref", "--contains", hash, "--format=%(refname)", ref)
	if err != nil {
		return errors.Wrapf(err, "check %s is reachable from %s", commit, ref)
	}
	if slices.Contains(strings.Fields(string(bs)), ref) {
		return nil
	}

	// The branch is missing, or does not contain the commit. show-ref
	// --verify --quiet exits 1 when the ref does not exist.
	if _, err := util.Git("-C", repository, "show-ref", "--verify", "--quiet", ref); err != nil {
		if exitedWith(err, 1) {
			return errors.Wrapf(ErrBranchNotFound, "check %s exists", ref)
		}
		return errors.Wrapf(err, "check %s exists", ref)
	}
	return errors.Wrapf(ErrNotReachable, "check %s is reachable from %s", commit, ref)
}

func containsGoGit(repository, commit, branch string) error {
	r, err := git.PlainOpen(repository)
	if err != nil {
		return errors.Wrapf(err, "open %s", repository)
	}

	h, err := r.ResolveRevision(plumbing.Revision(commit))
	if err != nil {
		if branch != "" && errors.Is(err, plumbing.ErrReferenceNotFound) {
			return errors.Wrapf(ErrCommitNotFound, "resolve %s (the history may have been truncated or rewritten)", commit)
		}
		return errors.Wrapf(err, "resolve %s", commit)
	}
	if branch == "" {
		return nil
	}
	if err := checkFullHash(commit, h.String()); err != nil {
		return err
	}

	ref := plumbing.NewBranchReferenceName(branch)
	resolved, err := r.Reference(ref, true)
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return errors.Wrapf(ErrBranchNotFound, "check %s exists", ref)
		}
		return errors.Wrapf(err, "check %s exists", ref)
	}
	tip, err := r.CommitObject(resolved.Hash())
	if err != nil {
		return errors.Wrapf(err, "resolve %s", ref)
	}

	// (*object.Commit).IsAncestor reads every parent, so it fails on a
	// shallow repository, such as a dotgit vuls-data-db has truncated, where
	// the parents of the shallow commits are missing. Stop at those commits,
	// as git does. The walk yields only the commit, if it is reachable.
	shallow, err := r.Storer.Shallow()
	if err != nil {
		return errors.Wrap(err, "read shallow commits")
	}
	isCommit := object.CommitFilter(func(c *object.Commit) bool { return c.Hash == *h })
	isShallow := object.CommitFilter(func(c *object.Commit) bool { return slices.Contains(shallow, c.Hash) })
	iter := object.NewFilterCommitIter(tip, &isCommit, &isShallow)
	defer iter.Close()

	switch _, err := iter.Next(); {
	case errors.Is(err, io.EOF):
		return errors.Wrapf(ErrNotReachable, "check %s is reachable from %s", commit, ref)
	case err != nil:
		return errors.Wrapf(err, "check %s is reachable from %s", commit, ref)
	default:
		return nil
	}
}

// checkFullHash checks that commit, which resolved to the commit hash, is
// that commit's own full hash. Resolving peels an annotated tag, and takes an
// abbreviation, a ref name, or in go-git, a ref named like a missing hash.
func checkFullHash(commit, hash string) error {
	if !strings.EqualFold(commit, hash) {
		return errors.Wrapf(ErrCommitNotFound, "%s resolves to commit %s, but is not a commit's own full hash (e.g. an annotated tag's hash, an abbreviation or a ref name)", commit, hash)
	}
	return nil
}

// exitedWith reports whether err comes from a git that exited with code.
func exitedWith(err error, code int) bool {
	ee, ok := stderrors.AsType[*exec.ExitError](err)
	return ok && ee.ExitCode() == code
}
