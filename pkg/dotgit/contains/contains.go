package contains

import (
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
)

type CommitNotFoundError struct {
	Repository string
	Commit     string
	Err        error
}

func (e *CommitNotFoundError) Error() string {
	return fmt.Sprintf("commit %s not found in %s: %v", e.Commit, e.Repository, e.Err)
}

func (e *CommitNotFoundError) Unwrap() error { return e.Err }

func Contains(repository, commit string) error {
	r, err := git.PlainOpen(repository)
	if err != nil {
		return errors.Wrapf(err, "open %s", repository)
	}

	hash, err := r.ResolveRevision(plumbing.Revision(commit))
	if err != nil {
		return errors.Wrapf(err, "resolve %s", commit)
	}

	if _, err := r.CommitObject(*hash); err != nil {
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			return &CommitNotFoundError{
				Repository: repository,
				Commit:     commit,
				Err:        err,
			}
		}
		return errors.Wrap(err, "get commit")
	}

	return nil
}
