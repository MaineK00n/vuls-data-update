package log

import (
	"bufio"
	"bytes"
	"fmt"
	"iter"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/pkg/errors"
)

type options struct {
	useNativeGit bool
	from         string
	pathspecs    []string
	since        *time.Time
	until        *time.Time
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

type fromOption string

func (f fromOption) apply(opts *options) {
	opts.from = string(f)
}

func WithFrom(from string) Option {
	return fromOption(from)
}

type pathspecsOption []string

func (p pathspecsOption) apply(opts *options) {
	opts.pathspecs = []string(p)
}

func WithPathSpecs(pathspecs []string) Option {
	return pathspecsOption(pathspecs)
}

type sinceOption struct {
	since *time.Time
}

func (s sinceOption) apply(opts *options) {
	opts.since = s.since
}

func WithSince(since *time.Time) Option {
	return sinceOption{since: since}
}

type untilOption struct {
	until *time.Time
}

func (u untilOption) apply(opts *options) {
	opts.until = u.until
}

func WithUntil(until *time.Time) Option {
	return untilOption{until: until}
}

func Log(repository string, opts ...Option) (iter.Seq2[string, error], error) {
	options := &options{
		useNativeGit: true,
		from:         "",
		pathspecs:    nil,
		since:        nil,
		until:        nil,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	if options.useNativeGit {
		args := []string{"-C", repository, "log"}
		if options.since != nil {
			args = append(args, fmt.Sprintf("--since=%s", options.since.Format(time.RFC3339)))
		}
		if options.until != nil {
			args = append(args, fmt.Sprintf("--until=%s", options.until.Format(time.RFC3339)))
		}
		if options.from != "" {
			args = append(args, options.from)
		} else {
			args = append(args, "HEAD")
		}
		if len(options.pathspecs) > 0 {
			args = append(args, "--")
			args = append(args, options.pathspecs...)
		}

		cmd := exec.Command("git", args...)
		output, err := cmd.Output()
		if err != nil {
			return nil, errors.Wrapf(err, "exec %q", cmd.String())
		}
		return func(yield func(string, error) bool) {
			var sb strings.Builder
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				s := scanner.Text()
				if strings.HasPrefix(s, "commit ") && sb.Len() > 0 {
					if !yield(strings.TrimSuffix(sb.String(), "\n"), nil) {
						return
					}
					sb.Reset()
				}
				sb.WriteString(fmt.Sprintf("%s\n", s))
			}
			if sb.Len() > 0 {
				if !yield(sb.String(), nil) {
					return
				}
			}

			if err := scanner.Err(); err != nil {
				if !yield("", errors.Wrap(err, "scanner encounter error")) {
					return
				}
			}
		}, nil
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", repository)
	}

	hash, err := func() (plumbing.Hash, error) {
		if options.from == "" {
			ref, err := r.Head()
			if err != nil {
				return plumbing.ZeroHash, errors.Wrap(err, "get head")
			}
			return ref.Hash(), nil
		}

		hash, err := r.ResolveRevision(plumbing.Revision(options.from))
		if err != nil {
			return plumbing.ZeroHash, errors.Wrapf(err, "resolve %s", options.from)
		}
		return *hash, nil
	}()
	if err != nil {
		return nil, errors.Wrap(err, "resolve from")
	}

	rePathSpecs := make([]*regexp.Regexp, 0, len(options.pathspecs))
	for _, pathspec := range options.pathspecs {
		re, err := regexp.Compile(pathspec)
		if err != nil {
			return nil, errors.Wrapf(err, "compile %q", pathspec)
		}
		rePathSpecs = append(rePathSpecs, re)
	}

	iter, err := r.Log(&git.LogOptions{
		From: hash,
		PathFilter: func() func(string) bool {
			if len(rePathSpecs) == 0 {
				return nil
			}
			return func(path string) bool {
				for _, re := range rePathSpecs {
					if re.MatchString(path) {
						return true
					}
				}
				return false
			}
		}(),
		Since: options.since,
		Until: options.until,
	})
	if err != nil {
		return nil, errors.Wrap(err, "get commit history")
	}
	defer iter.Close()

	return func(yield func(string, error) bool) {
		if err := iter.ForEach(func(c *object.Commit) error {
			if !yield(c.String(), nil) {
				return storer.ErrStop
			}
			return nil
		}); err != nil {
			if !yield("", errors.Wrap(err, "iterate commit history")) {
				return
			}
		}
	}, nil
}
