package util

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// repositoryEnv is what `git rev-parse --local-env-vars` lists in git 2.56,
// less GIT_CONFIG_PARAMETERS and GIT_CONFIG_COUNT: the same split as
// prepare_other_repo_env in git's run-command.c. These variables belong to
// one repository. Most say where it, its work tree, index or objects are, or,
// for GIT_CONFIG, which file git config reads and writes, and git honors them
// over -C, which only changes the working directory. git sets some of them
// for the processes it starts: hooks such as pre-commit get GIT_INDEX_FILE,
// and in a linked worktree, hooks and the commands of git rebase -x get
// GIT_DIR. Inherited, they make git act on that repository instead of the one
// named. The two left out carry config values (git -c, and
// GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n>) rather than a location, so they are
// kept, and config passed through the environment still applies.
var repositoryEnv = []string{
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_CONFIG",
	"GIT_OBJECT_DIRECTORY",
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_IMPLICIT_WORK_TREE",
	"GIT_GRAFT_FILE",
	"GIT_INDEX_FILE",
	"GIT_NO_REPLACE_OBJECTS",
	"GIT_REPLACE_REF_BASE",
	"GIT_PREFIX",
	"GIT_SHALLOW_FILE",
	"GIT_COMMON_DIR",
}

// Git runs native git and returns its stdout. On failure, the error holds
// the command and its stderr.
//
// git runs without the variables that tie it to one repository (GIT_DIR,
// GIT_WORK_TREE, GIT_INDEX_FILE, GIT_CONFIG and the like), so it acts on the
// repository that -C or a path argument names even when this process runs
// from a git hook or git rebase -x. Config values passed through the
// environment (GIT_CONFIG_COUNT, GIT_CONFIG_PARAMETERS) still apply.
func Git(args ...string) ([]byte, error) {
	return GitWithStdin(nil, args...)
}

// GitWithStdin runs native git with stdin, in the environment Git describes,
// and returns its stdout.
func GitWithStdin(stdin io.Reader, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...)
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(repositoryEnv, name)
	})
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
