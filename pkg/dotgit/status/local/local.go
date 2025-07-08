package local

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type DotGitStatus struct {
	Name string    `json:"name"`
	Time time.Time `json:"time"`
	Size struct {
		Total  int64 `json:"total"`
		DotGit int64 `json:"dotgit"`
	} `json:"size"`
	Restored bool `json:"restored"`
}

func Status(dir string) (DotGitStatus, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return DotGitStatus{}, errors.Wrapf(err, "stat %q", dir)
	}

	var (
		total  int64
		dotgit int64
	)
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		i, err := d.Info()
		if err != nil {
			return errors.Wrap(err, "get file info")
		}

		total += i.Size()
		if strings.HasPrefix(path, filepath.Join(dir, ".git")) {
			dotgit += i.Size()
		}

		return nil
	}); err != nil {
		return DotGitStatus{}, errors.Wrapf(err, "walk %q", dir)
	}

	return DotGitStatus{
		Name: dir,
		Time: info.ModTime(),
		Size: struct {
			Total  int64 `json:"total"`
			DotGit int64 `json:"dotgit"`
		}{
			Total:  total,
			DotGit: dotgit,
		},
		Restored: total != dotgit,
	}, nil
}
