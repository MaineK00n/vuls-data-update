package git

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
)

type commit struct {
	Path   string `json:"path"`
	Msg    string `json:"msg"`
	Author struct {
		Name  string    `json:"name"`
		Email string    `json:"email"`
		When  time.Time `json:"when"`
	} `json:"author"`
}

func Populate(dir, datapath string) (string, error) {
	if err := os.MkdirAll(filepath.Join(dir, filepath.Base(datapath)), 0755); err != nil {
		return "", errors.Wrapf(err, "mkdir %s", filepath.Join(dir, filepath.Base(datapath)))
	}

	r, err := git.PlainInitWithOptions(filepath.Join(dir, filepath.Base(datapath)), &git.PlainInitOptions{
		InitOptions: git.InitOptions{
			DefaultBranch: plumbing.NewBranchReferenceName("main"),
		},
		Bare: false,
	})
	if err != nil {
		return "", errors.Wrapf(err, "git init %s", filepath.Join(dir, filepath.Base(datapath)))
	}

	w, err := r.Worktree()
	if err != nil {
		return "", errors.Wrapf(err, "git worktree %s", filepath.Join(dir, filepath.Base(datapath)))
	}

	f, err := os.Open(filepath.Join(datapath, "commits.json"))
	if err != nil {
		return "", errors.Wrapf(err, "open %s", filepath.Join(datapath, "commits.json"))
	}
	defer f.Close()

	var commits []commit
	if err := json.NewDecoder(f).Decode(&commits); err != nil {
		return "", errors.Wrap(err, "decode json")
	}

	for _, c := range commits {
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
