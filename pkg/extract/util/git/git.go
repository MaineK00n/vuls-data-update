package git

import (
	"github.com/go-git/go-git/v5"
	"github.com/pkg/errors"

	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
)

func IsGitRepository(path string) bool {
	_, err := git.PlainOpen(path)
	return err == nil
}

func GetOrigin(path string) (string, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", errors.Wrap(err, "open as git repository")
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return "", errors.Wrap(err, "get origin")
	}
	return remote.Config().URLs[0], nil
}

func GetDataSourceRepository(path string) (*repositoryTypes.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, errors.Wrap(err, "open as git repository")
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return nil, errors.Wrap(err, "get origin")
	}
	ref, err := repo.Head()
	if err != nil {
		return nil, errors.Wrap(err, "get HEAD")
	}

	c, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, errors.Wrap(err, "get HEAD commit")
	}

	return &repositoryTypes.Repository{
		URL:    remote.Config().URLs[0],
		Commit: ref.Hash().String(),
		Date:   &c.Author.When,
	}, nil
}
