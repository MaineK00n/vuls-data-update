// Package test provides the golden-tree comparison shared by the fetch tests.
package test

import (
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Diff compares the tree a Fetch wrote below gotDir with the golden tree below
// wantDir, reporting every file that differs, is missing or is unexpected, and
// returns the number of files compared.
//
// The comparison is byte for byte. A fetcher writes what it received and does
// so deterministically, so any difference at all is a regression; comparing
// parsed content would hide formatting changes that the extract step sees.
//
// Golden names are percent-escaped. Fetched files are named after advisory or
// definition IDs such as "RHSA-2023:7435" or "oval:com.redhat.rhsa:ste:...",
// and ":" is awkward to keep in a repository, so testdata/golden holds
// url.QueryEscape of the name the fetcher writes.
func Diff(t *testing.T, wantDir, gotDir string) int {
	t.Helper()

	return DiffFunc(t, wantDir, gotDir, func(path string) (string, error) {
		bs, err := os.ReadFile(path)
		return string(bs), err
	})
}

// DiffFunc is Diff with the files decoded by decode before they are compared.
// Use it only where a fetcher cannot write a byte-identical tree — for example
// when it emits a slice in a nondeterministic order and the test has to pass
// cmpopts.SortSlices.
func DiffFunc[T any](t *testing.T, wantDir, gotDir string, decode func(path string) (T, error), opts ...cmp.Option) int {
	t.Helper()

	want := walk(t, wantDir, false)
	got := walk(t, gotDir, true)

	if d := cmp.Diff(slices.Sorted(maps.Keys(want)), slices.Sorted(maps.Keys(got))); d != "" {
		t.Errorf("files (-expected +got):\n%s", d)
	}

	var n int
	for _, name := range slices.Sorted(maps.Keys(want)) {
		gotPath, ok := got[name]
		if !ok {
			continue
		}

		w, err := decode(want[name])
		if err != nil {
			t.Errorf("decode %s. err: %v", want[name], err)
			continue
		}

		g, err := decode(gotPath)
		if err != nil {
			t.Errorf("decode %s. err: %v", gotPath, err)
			continue
		}

		if d := cmp.Diff(w, g, opts...); d != "" {
			t.Errorf("%s (-expected +got):\n%s", name, d)
		}
		n++
	}

	return n
}

// walk maps every file below root to its path, keyed by the slash-separated
// path relative to root. With escape set the last element is percent-escaped,
// so a tree a fetcher just wrote is keyed the way the golden tree is stored.
// A root that does not exist is an empty tree, not an error: a sad path may
// legitimately produce nothing.
func walk(t *testing.T, root string, escape bool) map[string]string {
	t.Helper()

	out := make(map[string]string)
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if escape {
			dir, file := filepath.Split(rel)
			rel = filepath.Join(dir, url.QueryEscape(file))
		}

		out[filepath.ToSlash(rel)] = p

		return nil
	}); err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s. err: %v", root, err)
	}

	return out
}
