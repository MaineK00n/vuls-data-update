package util

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuls-data-update")
	return dir
}

func ExtractDotgitTarZst(r io.Reader, dir string) error {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return errors.Wrap(err, "new zstd reader")
	}
	defer zr.Close() //nolint:errcheck

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		ss := strings.Split(hdr.Name, string(os.PathSeparator))
		if len(ss) < 2 {
			return errors.Errorf("unexpected tar header name. expected: %q, actual: %q", "<dir>/(...)", hdr.Name)
		}
		p := filepath.Join(dir, filepath.Join(ss[1:]...))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(p, 0755); err != nil {
				return errors.Wrapf(err, "mkdir %s", p)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Dir(p))
			}

			if err := func() error {
				f, err := os.Create(p)
				if err != nil {
					return errors.Wrapf(err, "create %s", p)
				}
				defer f.Close() //nolint:errcheck

				if _, err := io.Copy(f, tr); err != nil {
					return errors.Wrapf(err, "copy to %s", p)
				}

				return nil
			}(); err != nil {
				return errors.Wrapf(err, "create %s", p)
			}
		}
	}

	return nil
}
