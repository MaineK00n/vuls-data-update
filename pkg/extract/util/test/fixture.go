package test

import (
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// QueryUnescapeFileTree copies the file tree at fixturePath into dir by
// query-unescaping file names, and returns the copy's path,
// <dir>/(basename of fixturePath). Callers pass t.TempDir() as dir.
func QueryUnescapeFileTree(dir, fixturePath string) (string, error) {
	rawPath := filepath.Join(dir, filepath.Base(fixturePath))
	if err := os.MkdirAll(rawPath, fs.ModePerm); err != nil {
		return "", errors.Wrapf(err, "mkdir %s", rawPath)
	}

	if err := filepath.WalkDir(fixturePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(fixturePath, path)
		if err != nil {
			return errors.Wrapf(err, "rel %s", path)
		}
		unescaped, err := url.QueryUnescape(rel)
		if err != nil {
			return errors.Wrapf(err, "query unescape %s", rel)
		}
		// A name that unescapes to something reaching outside the destination
		// would be materialized outside the temp directory, where the test
		// would neither find it nor clean it up.
		if !filepath.IsLocal(unescaped) {
			return errors.Errorf("unexpected fixture name. expected: %q to unescape to a path under the fixture root, actual: %q", rel, unescaped)
		}

		targetDir := filepath.Join(rawPath, filepath.Dir(unescaped))
		if err := os.MkdirAll(targetDir, fs.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", targetDir)
		}
		if err := os.Link(path, filepath.Join(rawPath, unescaped)); err != nil {
			return errors.Wrapf(err, "link %s", filepath.Join(rawPath, unescaped))
		}

		return nil
	}); err != nil {
		return "", errors.Wrapf(err, "walk %s", fixturePath)
	}

	return rawPath, nil
}
