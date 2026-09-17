package test

import (
	"bytes"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
)

type options struct {
	replaces [][2]string
}

type Option interface {
	apply(*options)
}

type replaceOption [2]string

func (r replaceOption) apply(opts *options) {
	opts.replaces = append(opts.replaces, r)
}

// WithReplace rewrites old to new in every file the fetcher wrote, before it is
// compared. It is for the one value a fixture cannot hold fixed: the test
// server's own base URL, which lands in the output and changes on every run.
func WithReplace(old, new string) Option {
	return replaceOption{old, new}
}

// Diff compares the tree a fetcher or extractor wrote under gotDir against the golden tree
// at goldenDir, and reports the difference as an error. Both trees are read
// whole and compared as maps keyed by path relative to their roots, so which
// files exist is part of the comparison: a file the fetcher failed to write is
// reported missing, and one it wrote that golden does not describe is reported
// extra.
//
// Golden stores file names URL-escaped and the writers do not, so the
// output tree is brought into golden's domain before the two are compared.
//
// Files are compared byte for byte rather than as parsed content: what is
// written is either upstream content worth keeping only if it reproduces
// exactly, or JSON written deterministically, so any difference at all is a
// regression. A test that needs its output sorted before it will compare is
// reporting a non-deterministic writer, not a comparison too strict.
//
// A goldenDir that does not exist reads as an empty tree, for the test case
// whose expected output is nothing at all: git cannot carry an empty directory.
func Diff(goldenDir, gotDir string, opts ...Option) error {
	options := &options{}
	for _, o := range opts {
		o.apply(options)
	}

	want, err := readTree(goldenDir, nil)
	if err != nil {
		return errors.Wrapf(err, "read %s", goldenDir)
	}

	got, err := readTree(gotDir, options.replaces)
	if err != nil {
		return errors.Wrapf(err, "read %s", gotDir)
	}

	if diff := cmp.Diff(want, escapeNames(got)); diff != "" {
		return errors.Errorf("(-expected +got):\n%s", diff)
	}

	return nil
}

func readTree(root string, replaces [][2]string) (map[string]string, error) {
	tree := make(map[string]string)

	switch ok, err := exists(root); {
	case err != nil:
		return nil, errors.Wrapf(err, "check %s", root)
	case !ok:
		return tree, nil
	}

	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return errors.Wrapf(err, "rel %s", path)
		}

		bs, err := os.ReadFile(path)
		if err != nil {
			return errors.Wrapf(err, "read %s", path)
		}
		for _, r := range replaces {
			bs = bytes.ReplaceAll(bs, []byte(r[0]), []byte(r[1]))
		}
		tree[rel] = string(bs)

		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "walk %s", root)
	}

	return tree, nil
}

// escapeNames re-keys a tree by the URL-escaped form of each file's base name,
// which is how golden stores them. Only the base name is escaped: directory
// components are stored raw on both sides.
func escapeNames(tree map[string]string) map[string]string {
	escaped := make(map[string]string, len(tree))
	for rel, content := range tree {
		dir, file := filepath.Split(rel)
		escaped[filepath.Join(dir, url.QueryEscape(file))] = content
	}

	return escaped
}

// exists reports whether path is there. Only its absence is an answer: any
// other stat failure is an error, so that a directory that cannot be read is
// not mistaken for one that holds nothing.
func exists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		return false, errors.Wrapf(err, "stat %s", path)
	}

	return true, nil
}
