package git

import (
	"encoding/json/v2"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
)

type repository struct {
	Branches []struct {
		Name   string `json:"name"`
		Remote string `json:"remote"`
	} `json:"branches"`
	Remotes []struct {
		Name string   `json:"name"`
		URLs []string `json:"urls"`
	} `json:"remotes"`
	Commits []struct {
		Path   string `json:"path"`
		Msg    string `json:"msg"`
		Author struct {
			Name  string    `json:"name"`
			Email string    `json:"email"`
			When  time.Time `json:"when"`
		} `json:"author"`
	} `json:"commits"`
}

func Populate(dir, datapath string) (string, error) {
	f, err := os.Open(filepath.Join(datapath, "repository.json"))
	if err != nil {
		return "", errors.Wrapf(err, "open %s", filepath.Join(datapath, "repository.json"))
	}
	defer f.Close()

	var fixtures repository
	if err := json.UnmarshalRead(f, &fixtures); err != nil {
		return "", errors.Wrap(err, "decode json")
	}

	if err := os.MkdirAll(filepath.Join(dir, filepath.Base(datapath)), 0755); err != nil {
		return "", errors.Wrapf(err, "mkdir %s", filepath.Join(dir, filepath.Base(datapath)))
	}

	repo, err := git.PlainInitWithOptions(filepath.Join(dir, filepath.Base(datapath)), &git.PlainInitOptions{
		InitOptions: git.InitOptions{
			DefaultBranch: func() plumbing.ReferenceName {
				if len(fixtures.Branches) == 0 {
					return ""
				}
				return plumbing.NewBranchReferenceName(fixtures.Branches[0].Name)
			}(),
		},
		Bare: false,
	})
	if err != nil {
		return "", errors.Wrapf(err, "git init %s", filepath.Join(dir, filepath.Base(datapath)))
	}

	for _, b := range fixtures.Branches {
		if err := repo.CreateBranch(&config.Branch{
			Name:   b.Name,
			Remote: b.Remote,
		}); err != nil {
			return "", errors.Wrapf(err, "create branch %s", b.Name)
		}
	}

	for _, remote := range fixtures.Remotes {
		if _, err := repo.CreateRemote(&config.RemoteConfig{
			Name: remote.Name,
			URLs: remote.URLs,
		}); err != nil {
			return "", errors.Wrapf(err, "create remote %s", remote.Name)
		}
	}

	w, err := repo.Worktree()
	if err != nil {
		return "", errors.Wrapf(err, "git worktree %s", filepath.Join(dir, filepath.Base(datapath)))
	}

	for _, c := range fixtures.Commits {
		if err := filepath.WalkDir(filepath.Join(datapath, c.Path), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			rel, err := filepath.Rel(filepath.Join(datapath, c.Path), path)
			if err != nil {
				return errors.Wrapf(err, "relative filepath. prefix: %q, path: %q", filepath.Join(datapath, c.Path), path)
			}

			switch {
			case d.IsDir():
				if err := os.MkdirAll(filepath.Join(dir, filepath.Base(datapath), rel), 0755); err != nil {
					return errors.Wrapf(err, "mkdir %s", filepath.Join(dir, filepath.Base(datapath), rel))
				}
				return nil
			default:
				src, err := os.Open(path)
				if err != nil {
					return errors.Wrapf(err, "open %s", path)
				}
				defer src.Close()

				dst, err := os.Create(filepath.Join(dir, filepath.Base(datapath), rel))
				if err != nil {
					return errors.Wrapf(err, "create %s", filepath.Join(dir, filepath.Base(datapath), rel))
				}
				defer dst.Close()

				if _, err := io.Copy(dst, src); err != nil {
					return errors.Wrapf(err, "copy %s", path)
				}

				return nil
			}
		}); err != nil {
			return "", errors.Wrapf(err, "cp -r %s/* %s", filepath.Join(datapath, c.Path), filepath.Join(dir, filepath.Base(datapath)))
		}

		if err := w.AddGlob("*"); err != nil {
			return "", errors.Wrap(err, "git add *")
		}

		if _, err := w.Commit(c.Msg, &git.CommitOptions{
			Author: &object.Signature{
				Name:  c.Author.Name,
				Email: c.Author.Email,
				When:  c.Author.When,
			},
		}); err != nil {
			return "", errors.Wrapf(err, "git commit %s", c.Path)
		}
	}

	return filepath.Join(dir, filepath.Base(datapath)), nil
}

func CommitHashes(dir string) ([]string, error) {
	r, err := git.PlainOpen(dir)
	if err != nil {
		return nil, errors.Wrapf(err, "git open %s", dir)
	}

	iter, err := r.CommitObjects()
	if err != nil {
		return nil, errors.Wrap(err, "commit objects")
	}

	var cs []object.Commit
	if err := iter.ForEach(func(c *object.Commit) error {
		if c == nil {
			return errors.New("commit is nil")
		}
		cs = append(cs, *c)
		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "for each commit object")
	}

	slices.SortFunc(cs, func(a, b object.Commit) int {
		return a.Committer.When.Compare(b.Committer.When)
	})

	hashes := make([]string, 0, len(cs))
	for _, c := range cs {
		hashes = append(hashes, c.Hash.String())
	}

	return hashes, nil
}
