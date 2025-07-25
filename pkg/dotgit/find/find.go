package find

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"regexp"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
)

type options struct {
	useNativeGit bool
	treeish      string
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

type FileObject struct {
	Name string `json:"name,omitempty"`
	Mode string `json:"mode,omitempty"`
	Type string `json:"type,omitempty"`
	Hash string `json:"hash,omitempty"`
	Size int64  `json:"size,omitempty"`
}

func Find(repository, expression string, opts ...Option) ([]FileObject, error) {
	options := &options{
		useNativeGit: true,
		treeish:      "main",
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	regexp, err := regexp.Compile(expression)
	if err != nil {
		return nil, errors.Wrapf(err, "compile %s", expression)
	}

	if options.useNativeGit {
		cmd := exec.Command("git", "-C", repository, "ls-tree", "-r", "--format", `{"mode":"%(objectmode)","type":"%(objecttype)","hash":"%(objectname)","size":%(objectsize),"name":"%(path)"}`, options.treeish)
		output, err := cmd.Output()
		if err != nil {
			return nil, errors.Wrapf(err, "exec %q", cmd.String())
		}

		var fs []FileObject
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			var f FileObject
			if err := json.Unmarshal([]byte(scanner.Text()), &f); err != nil {
				return nil, errors.Wrapf(err, "unmarshal %q", scanner.Text())
			}
			if regexp.MatchString(f.Name) {
				fs = append(fs, f)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, errors.Wrap(err, "scanner encounter error")
		}

		return fs, nil
	}

	r, err := git.PlainOpen(repository)
	if err != nil {
		return nil, errors.Wrapf(err, "open %s", repository)
	}

	hash, err := r.ResolveRevision(plumbing.Revision(options.treeish))
	if err != nil {
		return nil, errors.Wrapf(err, "resolve %s", options.treeish)
	}

	commit, err := r.CommitObject(*hash)
	if err != nil {
		return nil, errors.Wrapf(err, "get commit %s", hash)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, errors.Wrapf(err, "get tree %s", commit.Hash)
	}

	walker := object.NewTreeWalker(tree, true, nil)
	defer walker.Close()

	var fs []FileObject
	for {
		path, entry, err := walker.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.Wrapf(err, "next %s", path)
		}

		if entry.Mode.IsFile() && regexp.MatchString(path) {
			f, err := tree.TreeEntryFile(&entry)
			if err != nil {
				return nil, errors.Wrapf(err, "get file %s", path)
			}

			fs = append(fs, FileObject{
				Name: f.Name,
				Mode: f.Mode.String(),
				Type: f.Type().String(),
				Hash: f.Hash.String(),
				Size: f.Size,
			})
		}
	}

	return fs, nil
}
