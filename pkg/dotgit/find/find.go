package find

import (
	"bufio"
	"bytes"
	"encoding/json/v2"
	"regexp"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	treeish string
}

type Option interface {
	apply(*options)
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
		treeish: "main",
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	regexp, err := regexp.Compile(expression)
	if err != nil {
		return nil, errors.Wrapf(err, "compile %s", expression)
	}

	output, err := util.Git("-C", repository, "ls-tree", "-r", "--format", `{"mode":"%(objectmode)","type":"%(objecttype)","hash":"%(objectname)","size":%(objectsize),"name":"%(path)"}`, options.treeish)
	if err != nil {
		return nil, errors.Wrapf(err, "list tree %s", options.treeish)
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
