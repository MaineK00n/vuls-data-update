package show

import (
	stderrors "errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	useNativeGit bool
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

// Commit is a commit's full hash and the times it was authored and committed.
//
// The times are in UTC. They hold the instant the commit records, to the
// second, but not the UTC offset it records.
type Commit struct {
	Hash          string    `json:"hash"`
	AuthorTime    time.Time `json:"author_time,omitzero"`
	CommitterTime time.Time `json:"committer_time,omitzero"`
}

// Show returns the commit that revision names in repository. An annotated tag
// names the commit it points to. A revision that does not name exactly one
// commit, such as a missing one, is an error.
//
// Native git reads the times through raw placeholders (%at, %ct) with
// --no-show-signature, so git config such as log.showSignature cannot add
// text to what it parses. The go-git path resolves revision with
// util.ResolveRevision, which knows fewer revision forms than git: it refuses
// a revision with a part that go-git would skip or read otherwise, such as
// main^{tree}, main:<path> or main@{1}, with an error that wraps
// util.ErrUnsupportedRevision, whether or not native git returns a commit for
// it.
func Show(repository, revision string, opts ...Option) (Commit, error) {
	options := &options{
		useNativeGit: true,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.useNativeGit {
		// --verify takes exactly one object name, so a range is an error.
		// --end-of-options keeps a revision starting with "-" from being read
		// as an option. With --quiet, a name that does not resolve exits 1,
		// while other failures, such as no repository, exit 128.
		bs, err := util.Git("-C", repository, "rev-parse", "--verify", "--quiet", "--end-of-options", revision)
		if err != nil {
			if ee, ok := stderrors.AsType[*exec.ExitError](err); ok && ee.ExitCode() == 1 {
				return Commit{}, errors.Wrapf(err, "%q does not name a commit", revision)
			}
			return Commit{}, errors.Wrapf(err, "resolve %s", revision)
		}
		object := strings.TrimSpace(string(bs))

		// ^{commit} peels an annotated tag to its commit, and fails for a tree
		// or a blob, and for a full hash of no object, which the call above
		// prints without looking it up. It is not appended to revision in that
		// call, because in :/<text> git reads it as part of the text.
		bs, err = util.Git("-C", repository, "rev-parse", "--verify", "--quiet", fmt.Sprintf("%s^{commit}", object))
		if err != nil {
			if ee, ok := stderrors.AsType[*exec.ExitError](err); ok && ee.ExitCode() == 1 {
				return Commit{}, errors.Wrapf(err, "%q does not name a commit", revision)
			}
			return Commit{}, errors.Wrapf(err, "peel %s", object)
		}
		hash := strings.TrimSpace(string(bs))

		bs, err = util.Git("-C", repository, "show", "--no-patch", "--no-show-signature", "--format=%at %ct", "--end-of-options", hash)
		if err != nil {
			return Commit{}, errors.Wrapf(err, "show %s", hash)
		}

		at, ct, ok := strings.Cut(strings.TrimSuffix(string(bs), "\n"), " ")
		if !ok {
			return Commit{}, errors.Errorf("unexpected show output. expected: %q, actual: %q", "<author time> <committer time>\n", bs)
		}
		authorTime, err := strconv.ParseInt(at, 10, 64)
		if err != nil {
			return Commit{}, errors.Wrapf(err, "parse author time in %q", bs)
		}
		committerTime, err := strconv.ParseInt(ct, 10, 64)
		if err != nil {
			return Commit{}, errors.Wrapf(err, "parse committer time in %q", bs)
		}

		return Commit{
			Hash:          hash,
			AuthorTime:    time.Unix(authorTime, 0).UTC(),
			CommitterTime: time.Unix(committerTime, 0).UTC(),
		}, nil
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return Commit{}, errors.Wrapf(err, "open %s", repository)
	}

	hash, err := util.ResolveRevision(r, revision)
	if err != nil {
		// go-git returns ErrObjectNotFound for a parent that is not in the
		// repository, such as that of the shallow commit of a shallow clone,
		// where native git exits 1 too. A refusal, which wraps
		// util.ErrUnsupportedRevision, is neither: the revision may name a
		// commit that only native git resolves.
		if errors.Is(err, plumbing.ErrReferenceNotFound) || errors.Is(err, plumbing.ErrObjectNotFound) {
			return Commit{}, errors.Wrapf(err, "%q does not name a commit", revision)
		}
		return Commit{}, errors.Wrapf(err, "resolve %s", revision)
	}

	c, err := r.CommitObject(*hash)
	if err != nil {
		return Commit{}, errors.Wrapf(err, "get commit %s", hash)
	}

	return Commit{
		Hash:          c.Hash.String(),
		AuthorTime:    c.Author.When.UTC(),
		CommitterTime: c.Committer.When.UTC(),
	}, nil
}
