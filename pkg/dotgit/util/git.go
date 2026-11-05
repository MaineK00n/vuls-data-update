package util

import (
	"bytes"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// Git runs native git and returns its stdout. On failure, the error holds
// the command and its stderr.
func Git(args ...string) ([]byte, error) {
	return GitWithStdin(nil, args...)
}

// GitWithStdin runs native git with stdin and returns its stdout.
func GitWithStdin(stdin io.Reader, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Stdin = stdin
	cmd.Stderr = &stderr
	bs, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "exec %q, stderr: %q", cmd.String(), stderr.String())
	}
	return bs, nil
}

// DiskUsage is the on-disk size of the objects revs reach in the repository
// at dir, as `git rev-list --objects --disk-usage` counts them: compressed,
// and as deltas where git stored them so. It needs git 2.31 or later.
func DiskUsage(dir string, revs ...string) (int64, error) {
	bs, err := Git(append([]string{"-C", dir, "rev-list", "--objects", "--disk-usage"}, revs...)...)
	if err != nil {
		return 0, errors.Wrap(err, "rev-list")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(string(bs)), 10, 64)
	if err != nil {
		return 0, errors.Wrapf(err, "parse %q", bs)
	}

	return n, nil
}
