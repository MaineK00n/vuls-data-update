package diff

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type gitRepo struct {
	name             string
	url              string
	dir              string
	old              string
	oldRemote        remote
	new              string
	newRemote        remote
	remotes          map[string]remote
	filter           string
	diffAlg          string
	archiveExhausted bool
}

type remote struct {
	name         string
	url          string
	archiveIndex int
	partial      bool
}

func (g *gitRepo) prepare() error {
	if _, err := os.Stat(g.dir); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return errors.Wrapf(err, "stat. dir: %s", g.dir)
		}

		if err := g.init(); err != nil {
			return errors.Wrapf(err, "git init")
		}
		if err := g.addRemoteAndFetch(remote{
			name:         "origin",
			url:          g.url,
			archiveIndex: 0, // latest
			partial:      true,
		}); err != nil {
			return errors.Wrapf(err, "add remote and fetch")
		}
	}

	cmd, stdout, stderr, err := execGitCmd(g.dir, "remote", "--verbose")
	if err != nil {
		return errors.Wrapf(err, "git remote. command: %s, stdout: %s, stderr: %s", cmd.String(), stdout, stderr)
	}
	for _, s := range strings.Split(stdout, "\n") {
		ss := strings.Fields(s)
		if len(ss) == 0 {
			continue
		}
		if len(ss) < 3 {
			log.Printf("[WARN] unknown remote format. remote: %q", s)
			continue
		}
		if ss[2] != "(push)" {
			continue
		}

		suffix, found := strings.CutPrefix(ss[1], strings.TrimSuffix(g.url, ".git"))
		if !found {
			log.Printf("[WARN] unexpected remote url. expected prefix: %s, actual: %s", strings.TrimSuffix(g.url, ".git"), ss[1])
			continue
		}

		cmd, partialfilter, stderr, err := execGitCmd(g.dir, "config", fmt.Sprintf("remote.%s.partialclonefilter", ss[0]))
		if err != nil && cmd.ProcessState.ExitCode() != 1 {
			return errors.Wrapf(err, "git config. command: %s, stdout: %s, stderr: %s", cmd.String(), partialfilter, stderr)
		}

		ai, err := func() (int, error) {
			suffix, found = strings.CutPrefix(suffix, "-archive-")
			if !found {
				return 0, nil // not archived but latest remote
			}
			index, err := strconv.Atoi(strings.TrimSuffix(suffix, ".git"))
			if err != nil {
				return 0, errors.Wrap(err, "parse index number")
			}
			return index, nil
		}()
		if err != nil {
			log.Printf("[WARN] archive index not found. remote: %s, url: %s", ss[0], ss[1])
			continue
		}
		g.remotes[ss[0]] = remote{
			name:         ss[0],
			url:          ss[1],
			archiveIndex: ai,
			partial:      strings.TrimSpace(partialfilter) != "",
		}
	}

	if g.old != "" {
		if err := g.ensureCommitExists(g.old); err != nil {
			return errors.Wrapf(err, "ensure commit %s exists", g.old)
		}
		r, err := g.findRemote(g.old)
		if err != nil {
			return errors.Wrapf(err, "find old remote. commit: %s", g.old)
		}
		g.oldRemote = r
	}

	if g.new != "" {
		if err := g.ensureCommitExists(g.new); err != nil {
			return errors.Wrapf(err, "ensure commit %s exists", g.old)
		}
		r, err := g.findRemote(g.new)
		if err != nil {
			return errors.Wrapf(err, "find new remote. commit: %s", g.new)
		}
		g.newRemote = r
	}

	return nil
}

// ensureCommitExists confirms the existence of commit by "git ls-tree" commmand in tree steps:
// 1. just run the command
// 2. if commit not found, fetch all known remotes
// 3. if still not found, add archive repositories
func (g *gitRepo) ensureCommitExists(commit string) error {
	cmd, stdout, stderr, err := execGitCmd(g.dir, "ls-tree", "--name-only", commit)
	if err == nil {
		return nil
	}
	if !strings.Contains(stderr, "Not a valid object name") {
		return errors.Wrapf(err, "git ls-tree. command: %s, stdout: %s, stderr: %s", cmd.String(), stdout, stderr)
	}

	if err := g.fetchAll(); err != nil {
		return errors.Wrapf(err, "fetch all")
	}
	cmd, stdout, stderr, err = execGitCmd(g.dir, "ls-tree", "--name-only", commit)
	if err == nil {
		return nil
	}
	if !strings.Contains(stderr, "Not a valid object name") {
		return errors.Wrapf(err, "git ls-tree. command: %s, stdout: %s, stderr: %s", cmd.String(), stdout, stderr)
	}

	if err := g.addArchives(); err != nil {
		return errors.Wrapf(err, "add archive repositories")
	}
	cmd, stdout, stderr, err = execGitCmd(g.dir, "ls-tree", "--name-only", commit)
	if err == nil {
		return nil
	}
	if !strings.Contains(stderr, "Not a valid object name") {
		return errors.Wrapf(err, "git ls-tree. command: %s, stdout: %s, stderr: %s", cmd.String(), stdout, stderr)
	}

	return errors.Errorf("commit: %s is not in either latest or archive remotes", commit)
}

func (g *gitRepo) addArchives() error {
	if g.archiveExhausted {
		return nil
	}

	indexes := make([]int, 0, len(g.remotes))
	for _, r := range g.remotes {
		indexes = append(indexes, r.archiveIndex)
	}

	for index := 1; true; index++ {
		if slices.Contains(indexes, index) {
			continue
		}

		url := fmt.Sprintf("%s-archive-%d.git", strings.TrimSuffix(g.url, ".git"), index)
		ok, err := g.exists(url)
		if err != nil {
			return errors.Wrapf(err, "archive exists. index: %d", index)
		}

		switch ok {
		case true:
			if err := g.addRemoteAndFetch(remote{
				name:         fmt.Sprintf("archive-%d", index),
				url:          url,
				archiveIndex: index,
				partial:      true,
			}); err != nil {
				return errors.Wrapf(err, "git remote add. url: %s", url)
			}
		case false:
			g.archiveExhausted = true
			return nil
		}
	}

	return nil
}

func (g gitRepo) getFileDiff(oldPath, newPath string) (FileDiff, error) {
	contentDiff, err := g.showDiff(oldPath, newPath)
	if err != nil {
		return FileDiff{}, errors.Wrapf(err, "show diff")
	}

	return FileDiff{
		Path: Path{
			Old: oldPath,
			New: newPath,
		},
		URL: URL{
			Old: func() string {
				if oldPath == "" {
					return ""
				}
				return g.blobURL(g.oldRemote, g.old, oldPath)
			}(),
			New: func() string {
				if newPath == "" {
					return ""
				}
				return g.blobURL(g.newRemote, g.new, newPath)
			}(),
		},
		Diff: contentDiff,
	}, nil
}

func (g gitRepo) getCommitRange() CommitRange {
	return CommitRange{
		Old: g.old,
		New: g.new,
		CompareURL: func() string {
			if g.old == "" || g.new == "" {
				return ""
			}
			if !strings.HasPrefix(g.url, "https://github.com") {
				return ""
			}
			return fmt.Sprintf("%s/compare/%s:%s..%s:%s",
				strings.TrimSuffix(g.url, ".git"),
				strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(g.oldRemote.url, "https://github.com/"), ".git"), "/", ":"), g.old,
				strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(g.newRemote.url, "https://github.com/"), ".git"), "/", ":"), g.new,
			)
		}(),
	}
}

func (g gitRepo) listTree(commit string) ([]string, error) {
	cmd, stdout, stderr, err := execGitCmd(g.dir, "ls-tree", "-r", "--name-only", commit)
	if err != nil {
		return nil, errors.Wrapf(err, "git ls-tree. command: %s, stdout: %s, stderr: %s", cmd.String(), stdout, stderr)
	}

	return strings.Split(stdout, "\n"), nil
}

func (g gitRepo) blobURL(remote remote, commit, path string) string {
	if !strings.HasPrefix(g.url, "https://github.com") {
		return ""
	}

	return fmt.Sprintf("%s/blob/%s/%s", strings.TrimSuffix(remote.url, ".git"), commit, path)
}

func (g gitRepo) findRemote(commit string) (remote, error) {
	for _, r := range g.remotes {
		head := fmt.Sprintf("%s/main", r.name)
		cmd, stdout, stderr, err := execGitCmd(g.dir, "merge-base", "--is-ancestor", commit, head)
		switch cmd.ProcessState.ExitCode() {
		case 0:
			return r, nil
		case 1:
			continue
		default:
			return remote{}, errors.Wrapf(err, "git merge-base. command: %s, stdout: %s, stderr: %s", cmd.String(), stdout, stderr)
		}
	}

	return remote{}, errors.Errorf("commit not included in any remote. commit: %s", commit)
}

func (g gitRepo) showDiff(oldPath, newPath string) (string, error) {
	if oldPath == "" && newPath == "" {
		return "", errors.Errorf("old and new paths are empty. repository: %s", g.name)
	}

	if oldPath != "" && newPath != "" {
		cmd, stdout, stderr, err := execGitCmd(g.dir, "diff", "--diff-algorithm", g.diffAlg, g.old, g.new, "--", oldPath, newPath)
		if err != nil {
			return "", errors.Wrapf(err, "git diff. command: %s, stdout: %s, stderr: %s", cmd.String(), stdout, stderr)
		}
		return stdout, nil
	}

	// following cases are only either old or new is specified, mimic diff by adding +/- prefix to blob lines

	if oldPath != "" {
		blob, err := g.showBlob(g.old, oldPath)
		if err != nil {
			return "", errors.Wrapf(err, "git show")
		}
		prefixed, err := addPrefix(blob, "-")
		if err != nil {
			return "", errors.Wrapf(err, "add prefix")
		}
		return prefixed, nil
	}

	blob, err := g.showBlob(g.new, newPath)
	if err != nil {
		return "", errors.Wrapf(err, "git show")
	}
	prefixed, err := addPrefix(blob, "+")
	if err != nil {
		return "", errors.Wrapf(err, "add prefix")
	}
	return prefixed, nil
}

func (g gitRepo) addRemoteAndFetch(r remote) error {
	cmd, _, stderr, err := execGitCmd(g.dir, "remote", "add", r.name, r.url)
	if err != nil {
		return errors.Wrapf(err, "git remote add. command: %s, stderr: %s", cmd.String(), stderr)
	}

	g.remotes[r.name] = r
	if err := g.fetch(r.name); err != nil {
		return errors.Wrapf(err, "git fetch. remote: %s", r.name)
	}

	return nil
}

func (g gitRepo) init() error {
	if err := os.MkdirAll(g.dir, fs.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", g.dir)
	}

	cmd, _, stderr, err := execGitCmd(g.dir, "init", "--bare")
	if err != nil {
		return errors.Wrapf(err, "git init. command: %s, stderr: %s", cmd.String(), stderr)
	}

	return nil
}

func (g gitRepo) fetchAll() error {
	for _, r := range g.remotes {
		if err := g.fetch(r.name); err != nil {
			return errors.Wrapf(err, "fetch remote %s", r.name)
		}
	}
	return nil
}

func (g gitRepo) fetch(remote string) error {
	r, found := g.remotes[remote]
	if !found {
		return errors.Errorf("no remote. name: %s", remote)
	}

	args := []string{remote}
	if r.partial {
		args = []string{fmt.Sprintf("--filter=%s", g.filter), remote}
	}
	cmd, _, stderr, err := execGitCmd(g.dir, "fetch", args...)
	if err != nil {
		return errors.Wrapf(err, "git fetch. command: %s, stderr: %s", cmd.String(), stderr)
	}
	return nil
}

func (g gitRepo) showBlob(commit, path string) (string, error) {
	cmd, stdout, stderr, err := execGitCmd(g.dir, "show", fmt.Sprintf("%s:%s", commit, path))
	if err != nil {
		return "", errors.Wrapf(err, "git show. command: %s, stderr: %s", cmd.String(), stderr)
	}
	return stdout, nil
}

func (g gitRepo) exists(url string) (bool, error) {
	cmd, _, stderr, err := execGitCmd(g.dir, "ls-remote", "--exit-code", url, "main")
	if err != nil {
		if strings.Contains(stderr, "Could not read from remote repository") || strings.Contains(stderr, "could not read Username") || strings.Contains(stderr, "access denied or repository not exported") {
			return false, nil
		}
		return false, errors.Wrapf(err, "git show. command: %s, stderr: %s", cmd.String(), stderr)
	}

	return true, nil
}

func execGitCmd(dir, subCmd string, args ...string) (*exec.Cmd, string, string, error) {
	cmd := exec.Command("git", slices.Concat([]string{subCmd}, args)...)
	cmd.Dir = dir
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=false")

	switch subCmd {
	case "fetch", "ls-tree", "show", "diff": // may take long, let's log timings
		log.Printf("[INFO] begin command: %s", cmd.String())
		start := time.Now()
		err := cmd.Run()
		elapsed := time.Since(start)
		log.Printf("[INFO] end command elaplsed: %d [msec] = %d [sec]", elapsed.Milliseconds(), (int64)(elapsed.Seconds()))
		return cmd, stdout.String(), stderr.String(), err
	default:
		err := cmd.Run()
		return cmd, stdout.String(), stderr.String(), err
	}
}

func addPrefix(lines, prefix string) (string, error) {
	var b bytes.Buffer
	s := bufio.NewScanner(strings.NewReader(lines))
	for s.Scan() {
		b.WriteString(prefix)
		b.WriteString(s.Text())
		b.WriteString("\n")
	}
	if err := s.Err(); err != nil {
		return "", errors.Wrapf(err, "add +/- prefix")
	}
	return b.String(), nil
}
