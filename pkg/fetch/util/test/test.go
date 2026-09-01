package test

import (
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Diff compares the tree a fetcher wrote under gotDir against the golden tree
// at goldenDir. Both trees are read whole and compared as maps keyed by path
// relative to their roots, so which files exist is part of the assertion: a
// file the fetcher failed to write is reported missing, and one it wrote that
// golden does not describe is reported extra.
//
// Golden file names are URL-escaped and the fetchers' output is not, so the got
// side is escaped to match. Only the base name is escaped; directory components
// are stored raw on both sides.
//
// A goldenDir that does not exist reads as an empty tree, for the test case
// whose expected output is nothing at all: git cannot carry an empty directory.
func Diff(t *testing.T, goldenDir, gotDir string) {
	t.Helper()

	if diff := cmp.Diff(readTree(t, goldenDir, false), readTree(t, gotDir, true)); diff != "" {
		t.Errorf("Fetch(). (-expected +got):\n%s", diff)
	}
}

func readTree(t *testing.T, root string, escape bool) map[string]string {
	t.Helper()

	tree := make(map[string]string)

	if _, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) {
		return tree
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
			return err
		}
		if escape {
			dir, file := filepath.Split(rel)
			rel = filepath.Join(dir, url.QueryEscape(file))
		}

		bs, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		tree[rel] = string(bs)

		return nil
	}); err != nil {
		t.Fatalf("walk %s: %s", root, err)
	}

	return tree
}
