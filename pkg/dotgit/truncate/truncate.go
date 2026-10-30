package truncate

import (
	"bytes"
	stderrors "errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	dir   string
	depth int
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type depthOption int

func (d depthOption) apply(opts *options) {
	opts.depth = int(d)
}

func WithDepth(depth int) Option {
	return depthOption(depth)
}

// Truncate copies the last depth commits of every branch of repository into a
// new repository, named after it, under the directory WithDir gives. The copy
// is shallow, has no tags, keeps the origin URL of repository, and has an
// index of HEAD but no working tree. repository itself is left as it is.
func Truncate(repository string, opts ...Option) (string, error) {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "dotgit", "truncate"),
		depth: 1,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.depth < 1 {
		return "", errors.Errorf("unexpected depth. expected: %q, actual: %d", ">= 1", options.depth)
	}

	src, err := filepath.Abs(repository)
	if err != nil {
		return "", errors.Wrapf(err, "absolute path of %s", repository)
	}

	dst, err := filepath.Abs(filepath.Join(options.dir, filepath.Base(src)))
	if err != nil {
		return "", errors.Wrapf(err, "absolute path of %s", filepath.Join(options.dir, filepath.Base(src)))
	}

	switch _, err := os.Stat(dst); {
	case err == nil:
		return "", errors.Errorf("%s already exists", dst)
	case errors.Is(err, fs.ErrNotExist):
	default:
		return "", errors.Wrapf(err, "stat %s", dst)
	}

	slog.Info("Truncate dotgit", slog.String("src", src), slog.String("dst", dst), slog.Int("depth", options.depth))

	if err := truncate(src, dst, options.depth); err != nil {
		if err2 := os.RemoveAll(dst); err2 != nil {
			err = stderrors.Join(err, errors.Wrapf(err2, "remove %s", dst))
		}
		return "", errors.Wrapf(err, "truncate %s to %s", src, dst)
	}

	return dst, nil
}

func truncate(src, dst string, depth int) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(dst))
	}

	// git clone honors --depth only through a URL; given a plain path, it
	// copies the whole repository. A tag would keep the commit it points to,
	// and up to depth commits behind it, so tags are left out.
	if _, err := git("clone", "--quiet", "--depth", strconv.Itoa(depth), "--no-single-branch", "--no-tags", "--no-checkout", fmt.Sprintf("file://%s", src), dst); err != nil {
		return errors.Wrap(err, "clone")
	}

	bs, err := git("-C", dst, "for-each-ref", "--format=%(refname:lstrip=3)", "refs/remotes/origin/")
	if err != nil {
		return errors.Wrap(err, "list cloned branches")
	}
	for line := range strings.Lines(string(bs)) {
		name := strings.TrimSuffix(line, "\n")
		if name == "HEAD" {
			continue
		}

		if _, err := git("-C", dst, "show-ref", "--verify", "--quiet", fmt.Sprintf("refs/heads/%s", name)); err == nil {
			continue
		}

		if _, err := git("-C", dst, "branch", "--quiet", name, fmt.Sprintf("refs/remotes/origin/%s", name)); err != nil {
			return errors.Wrapf(err, "create branch %s", name)
		}
	}

	// The clone's origin is the local path it was made from. Carry over the
	// origin of the repository instead, which vuls-data-db sets to its tag.
	bs, err = git("-C", src, "config", "--default", "", "--get", "remote.origin.url")
	if err != nil {
		return errors.Wrap(err, "get origin url")
	}
	switch url := strings.TrimSpace(string(bs)); url {
	case "":
		if _, err := git("-C", dst, "remote", "remove", "origin"); err != nil {
			return errors.Wrap(err, "remove origin")
		}
	default:
		if _, err := git("-C", dst, "remote", "set-url", "origin", url); err != nil {
			return errors.Wrapf(err, "set origin url to %s", url)
		}
	}

	// Without an index, git sees every file as deleted, and pull --restore
	// has nothing to restore from.
	if _, err := git("-C", dst, "reset", "--quiet"); err != nil {
		return errors.Wrap(err, "reset")
	}

	return nil
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
