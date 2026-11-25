package show

import (
	stderrors "errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

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
// Show reads the times through raw placeholders (%at, %ct) with
// --no-show-signature, so git config such as log.showSignature cannot add
// text to what it parses.
func Show(repository, revision string) (Commit, error) {
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
