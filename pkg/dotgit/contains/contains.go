package contains

import (
	stderrors "errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

var (
	// ErrBranchNotFound is the cause of the error Contains returns with
	// WithBranch when the repository has no such branch.
	ErrBranchNotFound = errors.New("branch not found")

	// ErrCommitNotFound is the cause of the error Contains returns with
	// WithBranch when the commit is not a commit in the repository. A commit
	// that used to be there can be gone: vuls-data-db keeps only the last
	// commits of a dotgit.
	ErrCommitNotFound = errors.New("commit not found, the history may have been truncated or rewritten")

	// ErrNotReachable is the cause of the error Contains returns with
	// WithBranch when the commit exists, but is neither the tip of the branch
	// nor an ancestor of it.
	ErrNotReachable = errors.New("commit not reachable from branch")
)

// reCommitHash matches the commit Contains takes with WithBranch: a full
// hash, of 40 hex digits (SHA-1) or 64 (SHA-256). An abbreviation is not
// taken: git resolves it as a ref first if one has that name, and it can name
// more than one commit.
var reCommitHash = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

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

// WithBranch makes Contains check that the commit, given as a full hash, is
// on branch, a branch name such as "main". An empty branch, the default,
// checks only that the object exists.
func WithBranch(branch string) Option {
	return branchOption(branch)
}

// Contains checks that repository has commit.
//
// By default, commit is any name of an object, and Contains checks only that
// the object exists.
//
// With WithBranch, Contains checks, in this order, that
//  1. the branch exists: refs/heads/<branch>, matched exactly;
//  2. commit, a full hash, names a commit object in repository;
//  3. the commit is the tip of the branch or an ancestor of it.
//
// The error of the first check that fails wraps ErrBranchNotFound,
// ErrCommitNotFound or ErrNotReachable. Neither branch nor commit is read as
// a revision, such as main~1, or as an option, and commit is looked up only
// as an object, never as a ref: a branch that is not a valid branch name, or
// a commit that is not a full hash, is an error that wraps none of them. So
// is a failure to run a check, which holds git's stderr.
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
		if !reCommitHash.MatchString(commit) {
			return errors.Errorf("unexpected commit. expected: %q, actual: %q", "a full commit hash of 40 or 64 hex digits", commit)
		}
		// git and go-git take hex digits in either case. rev-parse prints
		// them in lowercase, and the native check compares that with commit.
		commit = strings.ToLower(commit)

		if options.useNativeGit {
			return containsOnBranchNativeGit(repository, commit, options.branch)
		}
		return containsOnBranchGoGit(repository, commit, options.branch)
	}

	if options.useNativeGit {
		if _, err := util.Git("-C", repository, "cat-file", "-e", commit); err != nil {
			return errors.Wrapf(err, "check %s exists", commit)
		}
		return nil
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return errors.Wrapf(err, "open %s", repository)
	}

	if _, err := r.ResolveRevision(plumbing.Revision(commit)); err != nil {
		return errors.Wrapf(err, "resolve %s", commit)
	}

	return nil
}

func containsOnBranchNativeGit(repository, commit, branch string) error {
	ref := fmt.Sprintf("refs/heads/%s", branch)

	// show-ref --verify looks up exactly the full ref name it is given: no
	// other ref, and no revision. With --quiet, it exits 1 when the ref does
	// not exist; without, it exits 128, as for a broken repository, so the
	// hash is read once the ref is known to exist.
	if _, err := util.Git("-C", repository, "show-ref", "--verify", "--quiet", ref); err != nil {
		if exitedWith(err, 1) {
			return errors.Wrapf(ErrBranchNotFound, "check %s exists", ref)
		}
		return errors.Wrapf(err, "check %s exists", ref)
	}
	bs, err := util.Git("-C", repository, "show-ref", "--verify", "--hash", ref)
	if err != nil {
		return errors.Wrapf(err, "resolve %s", ref)
	}
	tip := strings.TrimSpace(string(bs))

	// rev-parse --verify --quiet exits 1 when the name does not resolve to a
	// commit: missing, or an object of another type. ^{commit} makes it read
	// the object; given a full hash alone, it prints the hash without looking
	// the object up. cat-file -e is not used: with ^{commit}, it exits 128 for
	// a missing object, as for a broken repository.
	//
	// A full hash of the repository's object format names that object even if
	// a ref has the same name. What rev-parse prints must still be commit
	// itself: ^{commit} peels an annotated tag to its commit, and a hash of
	// the other format, which is no object name here, is read as a ref name.
	bs, err = util.Git("-C", repository, "rev-parse", "--verify", "--quiet", "--end-of-options", fmt.Sprintf("%s^{commit}", commit))
	if err != nil {
		if exitedWith(err, 1) {
			return errors.Wrapf(ErrCommitNotFound, "check %s exists", commit)
		}
		return errors.Wrapf(err, "check %s exists", commit)
	}
	if hash := strings.TrimSpace(string(bs)); hash != commit {
		return errors.Wrapf(ErrCommitNotFound, "check %s exists: resolved to %s", commit, hash)
	}

	// merge-base --is-ancestor exits 0 when the first commit is the second or
	// an ancestor of it, 1 when it is not, and 128 on an error. It stops at
	// the shallow commits of a shallow repository.
	if _, err := util.Git("-C", repository, "merge-base", "--is-ancestor", commit, tip); err != nil {
		if exitedWith(err, 1) {
			return errors.Wrapf(ErrNotReachable, "check %s is reachable from %s", commit, ref)
		}
		return errors.Wrapf(err, "check %s is reachable from %s", commit, ref)
	}

	return nil
}

func containsOnBranchGoGit(repository, commit, branch string) error {
	r, err := git.PlainOpen(repository)
	if err != nil {
		return errors.Wrapf(err, "open %s", repository)
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

	// ResolveRevision is not used: it falls back to a ref that has the name
	// of a missing hash, and peels an annotated tag. CommitObject looks the
	// hash up only as an object, and reports a missing one, or one of
	// another type, as ErrObjectNotFound. go-git reads SHA-1 repositories
	// only, where a 64-digit hash cannot name an object.
	if !plumbing.IsHash(commit) {
		return errors.Wrapf(ErrCommitNotFound, "check %s exists", commit)
	}
	target, err := r.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			return errors.Wrapf(ErrCommitNotFound, "check %s exists", commit)
		}
		return errors.Wrapf(err, "check %s exists", commit)
	}

	// (*object.Commit).IsAncestor reads every parent, so it fails on a
	// shallow repository, such as a dotgit vuls-data-db has truncated, where
	// the parents of the shallow commits are missing. Stop at those commits,
	// as git does.
	shallow, err := r.Storer.Shallow()
	if err != nil {
		return errors.Wrap(err, "read shallow commits")
	}
	isLimit := object.CommitFilter(func(c *object.Commit) bool {
		return slices.Contains(shallow, c.Hash)
	})
	iter := object.NewFilterCommitIter(tip, nil, &isLimit)
	defer iter.Close()

	var reachable bool
	if err := iter.ForEach(func(c *object.Commit) error {
		if c.Hash == target.Hash {
			reachable = true
			return storer.ErrStop
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "check %s is reachable from %s", commit, ref)
	}
	if !reachable {
		return errors.Wrapf(ErrNotReachable, "check %s is reachable from %s", commit, ref)
	}

	return nil
}

// exitedWith reports whether err comes from a git that exited with code.
func exitedWith(err error, code int) bool {
	ee, ok := stderrors.AsType[*exec.ExitError](err)
	return ok && ee.ExitCode() == code
}
