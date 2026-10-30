package status

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type options struct {
	git bool
}

type Option interface {
	apply(*options)
}

type gitOption bool

func (o gitOption) apply(opts *options) {
	opts.git = bool(o)
}

// WithGit adds Git to the status. It runs native git.
func WithGit(git bool) Option {
	return gitOption(git)
}

type DotGitStatus struct {
	Name string    `json:"name"`
	Time time.Time `json:"time"`
	Size struct {
		Total  int64 `json:"total"`
		DotGit int64 `json:"dotgit"`
	} `json:"size"`
	Restored bool `json:"restored"`
	Git      *Git `json:"git,omitempty"`
}

// Git is what the repository holds: its branches, where its history was cut,
// and how much of it the branch tips take.
type Git struct {
	Branches map[string]Branch `json:"branches,omitempty"`
	Shallow  []string          `json:"shallow,omitempty"`
	Disk     Disk              `json:"disk"`
}

type Branch struct {
	Commit  string `json:"commit"`
	Commits int    `json:"commits"`
}

// Disk is the on-disk size of objects, as `git rev-list --disk-usage` counts
// them: compressed, and as deltas where git stored them so.
type Disk struct {
	// All is every object reachable from any ref.
	All int64 `json:"all"`
	// Tips is the objects the branch tips' trees reach, which is what a
	// shallow copy of depth 1 keeps. It comes out a little lower than such a
	// copy, as some of those objects are stored as deltas against history.
	Tips int64 `json:"tips"`
}

func Status(dir string, opts ...Option) (DotGitStatus, error) {
	options := &options{
		git: false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

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

	s := DotGitStatus{
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
	}

	if options.git {
		g, err := gitStatus(dir)
		if err != nil {
			return DotGitStatus{}, errors.Wrapf(err, "git status %q", dir)
		}
		s.Git = &g
	}

	return s, nil
}

func gitStatus(dir string) (Git, error) {
	bs, err := git("-C", dir, "for-each-ref", "--format=%(refname:lstrip=2) %(objectname)", "refs/heads/")
	if err != nil {
		return Git{}, errors.Wrap(err, "list branches")
	}

	branches := make(map[string]Branch)
	for line := range strings.Lines(string(bs)) {
		name, commit, ok := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
		if !ok {
			return Git{}, errors.Errorf("unexpected branch line. expected: %q, actual: %q", "<branch> <commit>", line)
		}

		bs, err := git("-C", dir, "rev-list", "--count", fmt.Sprintf("refs/heads/%s", name))
		if err != nil {
			return Git{}, errors.Wrapf(err, "count commits of %s", name)
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(bs)))
		if err != nil {
			return Git{}, errors.Wrapf(err, "parse commit count of %s", name)
		}

		branches[name] = Branch{
			Commit:  commit,
			Commits: n,
		}
	}

	bs, err = git("-C", dir, "rev-parse", "--path-format=absolute", "--git-path", "shallow")
	if err != nil {
		return Git{}, errors.Wrap(err, "locate shallow file")
	}
	path := strings.TrimSpace(string(bs))
	var shallow []string
	switch content, err := os.ReadFile(path); {
	case err == nil:
		shallow = strings.Fields(string(content))
		slices.Sort(shallow)
	case errors.Is(err, fs.ErrNotExist):
	default:
		return Git{}, errors.Wrapf(err, "read %s", path)
	}

	all, err := diskUsage(dir, "--all")
	if err != nil {
		return Git{}, errors.Wrap(err, "disk usage of all objects")
	}

	tips, err := diskUsage(dir, "--no-walk", "--branches")
	if err != nil {
		return Git{}, errors.Wrap(err, "disk usage of branch tips")
	}

	return Git{
		Branches: branches,
		Shallow:  shallow,
		Disk: Disk{
			All:  all,
			Tips: tips,
		},
	}, nil
}

func diskUsage(dir string, revs ...string) (int64, error) {
	bs, err := git(append([]string{"-C", dir, "rev-list", "--objects", "--disk-usage"}, revs...)...)
	if err != nil {
		return 0, errors.Wrap(err, "rev-list")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(string(bs)), 10, 64)
	if err != nil {
		return 0, errors.Wrapf(err, "parse %q", bs)
	}

	return n, nil
}

func git(args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stderr = &stderr
	bs, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "exec %q, stderr: %q", cmd.String(), stderr.String())
	}
	return bs, nil
}
