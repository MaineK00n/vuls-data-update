package grep

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pkg/errors"
)

type options struct {
	useNativeGit     bool
	treeish          string
	pathspecs        []string
	filesWithMatches bool
}

type Option interface {
	apply(*options)
}

type useNativeGitOption bool

func (o useNativeGitOption) apply(opts *options) {
	opts.useNativeGit = bool(o)
}

func WithUseNativeGit(native bool) Option {
	return useNativeGitOption(native)
}

type treeishOption string

func (t treeishOption) apply(opts *options) {
	opts.treeish = string(t)
}

func WithTreeish(id string) Option {
	return treeishOption(id)
}

type pathspecsOption []string

func (p pathspecsOption) apply(opts *options) {
	opts.pathspecs = []string(p)
}

func WithPathSpecs(pathspecs []string) Option {
	return pathspecsOption(pathspecs)
}

type filesWithMatchesOption bool

func (f filesWithMatchesOption) apply(opts *options) {
	opts.filesWithMatches = bool(f)
}

func WithFilesWithMatches(filesWithMatches bool) Option {
	return filesWithMatchesOption(filesWithMatches)
}

func Grep(repository string, patterns []string, opts ...Option) (string, error) {
	options := &options{
		useNativeGit:     true,
		treeish:          "main",
		pathspecs:        nil,
		filesWithMatches: false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.useNativeGit {
		args := []string{"-C", repository, "grep", "--line-number"}
		if options.filesWithMatches {
			args = append(args, "--files-with-matches")
		}
		for _, pattern := range patterns {
			args = append(args, "-e", pattern)
		}
		args = append(args, options.treeish)
		if len(options.pathspecs) > 0 {
			args = append(args, "--")
			args = append(args, options.pathspecs...)
		}

		cmd := exec.Command("git", args...)
		output, err := cmd.Output()
		if err != nil {
			return "", errors.Wrapf(err, "exec %q", cmd.String())
		}
		return string(output), nil
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return "", errors.Wrapf(err, "open %s", repository)
	}

	hash, err := r.ResolveRevision(plumbing.Revision(options.treeish))
	if err != nil {
		return "", errors.Wrapf(err, "resolve %s", options.treeish)
	}

	rePatterns := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return "", errors.Wrapf(err, "compile %q", pattern)
		}
		rePatterns = append(rePatterns, re)
	}

	rePathSpecs := make([]*regexp.Regexp, 0, len(options.pathspecs))
	for _, pathspec := range options.pathspecs {
		re, err := regexp.Compile(pathspec)
		if err != nil {
			return "", errors.Wrapf(err, "compile %q", pathspec)
		}
		rePathSpecs = append(rePathSpecs, re)
	}

	rs, err := r.Grep(&git.GrepOptions{
		CommitHash: *hash,
		Patterns:   rePatterns,
		PathSpecs:  rePathSpecs,
	})
	if err != nil {
		return "", errors.Wrap(err, "grep")
	}

	var sb strings.Builder
	for _, r := range rs {
		if options.filesWithMatches {
			sb.WriteString(fmt.Sprintf("%s:%s\n", r.TreeName, r.FileName))
		} else {
			sb.WriteString(fmt.Sprintf("%s\n", r.String()))
		}
	}
	return sb.String(), nil
}
