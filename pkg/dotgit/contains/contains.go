package contains

import (
	stderrors "errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

var (
	// ErrBranchNotFound is the cause of the error Contains returns with
	// WithBranch when the repository has no such branch.
	ErrBranchNotFound = errors.New("branch not found")

	// ErrCommitNotFound is the cause of the error Contains returns with
	// WithBranch when commit is not the full hash of a commit in the
	// repository. errors.Is matches pull.Pull's error with it too, when the
	// target of pull.WithCheckout names nothing in the pulled repository.
	ErrCommitNotFound = errors.New("commit not found")

	// ErrNotReachable is the cause of the error Contains returns with
	// WithBranch when the commit is neither the tip of the branch nor an
	// ancestor of it.
	ErrNotReachable = errors.New("commit not reachable from branch")
)

type options struct {
	branch string
}

type Option interface {
	apply(*options)
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
//
// A commit that a truncated history no longer has fails check 1, and the
// error says that the history may have been truncated or rewritten. In a
// shallow repository, a commit beyond the shallow commits where the history
// of the branch stops can still be there through another branch. It fails
// check 3, and the error says that the commit may be beyond the shallow
// boundary.
func Contains(repository, commit string, opts ...Option) error {
	options := &options{
		branch: "",
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.branch == "" {
		if _, err := util.Git("-C", repository, "cat-file", "-e", commit); err != nil {
			return errors.Wrapf(err, "check %s exists", commit)
		}
		return nil
	}

	if err := validateBranch(options.branch); err != nil {
		return errors.Wrapf(err, "validate branch %q", options.branch)
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
	// or a name like describe output (x-1-g<hash>) as that commit. The output
	// is split on newlines only, as a ref name can hold a Unicode space such
	// as U+00A0, which strings.Fields would split on.
	ref := fmt.Sprintf("refs/heads/%s", options.branch)
	bs, err = util.Git("-C", repository, "for-each-ref", "--contains", hash, "--format=%(refname)", ref)
	if err != nil {
		return errors.Wrapf(err, "check %s is reachable from %s", commit, ref)
	}
	if slices.Contains(strings.Split(string(bs), "\n"), ref) {
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

	bs, err = util.Git("-C", repository, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return errors.Wrapf(err, "check %s is shallow", repository)
	}
	return notReachable(commit, ref, strings.TrimSpace(string(bs)) == "true")
}

// notReachable returns the error for a commit that ref does not reach. In a
// shallow repository, the history of the branch stops at its shallow commits,
// and a commit beyond them can still be there through another branch, so the
// message says that the commit may be beyond the shallow boundary.
func notReachable(commit, ref string, shallow bool) error {
	if shallow {
		return errors.Wrapf(ErrNotReachable, "check %s is reachable from %s (the repository is shallow, so the commit may be beyond its shallow boundary)", commit, ref)
	}
	return errors.Wrapf(ErrNotReachable, "check %s is reachable from %s", commit, ref)
}

// checkFullHash checks that commit, which resolved to the commit hash, is
// that commit's own full hash. Resolving peels an annotated tag, and takes an
// abbreviation or a ref name.
func checkFullHash(commit, hash string) error {
	if !strings.EqualFold(commit, hash) {
		return errors.Wrapf(ErrCommitNotFound, "%s resolves to commit %s, but is not a commit's own full hash (e.g. an annotated tag's hash, an abbreviation or a ref name)", commit, hash)
	}
	return nil
}

// errInvalidBranch is the cause of the error validateBranch returns.
var errInvalidBranch = errors.New("invalid reference name")

// validateBranch checks that branch is a valid branch name: that it does not
// begin with "-", which git does not take as a branch name, and that
// refs/heads/<branch> is a valid ref name, which git check-ref-format says is
// not by exiting with 1. A name that is not, such as main~1, could read as a
// revision.
func validateBranch(branch string) error {
	if strings.HasPrefix(branch, "-") {
		return errInvalidBranch
	}
	if _, err := util.Git("check-ref-format", fmt.Sprintf("refs/heads/%s", branch)); err != nil {
		if exitedWith(err, 1) {
			return errInvalidBranch
		}
		return errors.Wrap(err, "check ref format")
	}
	return nil
}

// exitedWith reports whether err comes from a git that exited with code.
func exitedWith(err error, code int) bool {
	ee, ok := stderrors.AsType[*exec.ExitError](err)
	return ok && ee.ExitCode() == code
}
