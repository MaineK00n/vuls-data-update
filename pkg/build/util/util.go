package util

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dsnet/compress/bzip2"
	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"golang.org/x/exp/maps"
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuls-data-update")
	return dir
}

func SourceDir() string {
	pwd, err := os.Getwd()
	if err != nil {
		return filepath.Join(CacheDir(), "source")
	}
	srcDir := filepath.Join(pwd, "source")
	if f, err := os.Stat(srcDir); os.IsNotExist(err) || !f.IsDir() {
		return CacheDir()
	}
	return srcDir
}

func DestDir() string {
	pwd, err := os.Getwd()
	if err != nil {
		return filepath.Join(CacheDir(), "output")
	}
	destDir := filepath.Join(pwd, "output")
	if f, err := os.Stat(destDir); os.IsNotExist(err) || !f.IsDir() {
		return CacheDir()
	}
	return destDir
}

func Unique[T comparable](s []T) []T {
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return maps.Keys(m)
}

func BuildFilePath(name, compress string) string {
	switch compress {
	case "gzip":
		return fmt.Sprintf("%s.gz", name)
	case "bzip2":
		return fmt.Sprintf("%s.bz2", name)
	case "xz":
		return fmt.Sprintf("%s.xz", name)
	default:
		return name
	}
}

func Open(path, compress string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var bs []byte
	switch compress {
	case "":
		bs, err = io.ReadAll(f)
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
	case "gzip":
		r, err := gzip.NewReader(f)
		if err != nil {
			return nil, errors.Wrap(err, "create reader")
		}
		defer r.Close()

		bs, err = io.ReadAll(r)
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
	case "bzip2":
		r, err := bzip2.NewReader(f, nil)
		if err != nil {
			return nil, errors.Wrap(err, "create reader")
		}
		defer r.Close()

		bs, err = io.ReadAll(r)
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
	case "xz":
		r, err := xz.NewReader(f)
		if err != nil {
			return nil, errors.Wrap(err, "create reader")
		}

		bs, err = io.ReadAll(r)
		if err != nil {
			return nil, errors.Wrap(err, "read data")
		}
	default:
		return nil, errors.Errorf(`unexpected compress format. accepts: ["", "gzip", "bzip2", "xz"], received: "%s"`, compress)
	}

	return bs, nil
}

func Write(path string, bs []byte, compress string) error {
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", filepath.Dir(path))
	}

	var w io.WriteCloser
	switch compress {
	case "":
		var err error
		w, err = os.Create(path)
		if err != nil {
			return errors.Wrapf(err, "create %s", path)
		}
	case "gzip":
		f, err := os.Create(path)
		if err != nil {
			return errors.Wrapf(err, "create %s", path)
		}
		defer f.Close()

		w = gzip.NewWriter(f)
	case "bzip2":
		f, err := os.Create(path)
		if err != nil {
			return errors.Wrapf(err, "create %s", path)
		}
		defer f.Close()

		w, err = bzip2.NewWriter(f, &bzip2.WriterConfig{Level: bzip2.BestCompression})
		if err != nil {
			return errors.Wrap(err, "create writer")
		}
	case "xz":
		f, err := os.Create(path)
		if err != nil {
			return errors.Wrapf(err, "create %s", path)
		}
		defer f.Close()

		w, err = xz.NewWriter(f)
		if err != nil {
			return errors.Wrap(err, "create writer")
		}
	default:
		return errors.Errorf(`unexpected compress format. accepts: ["", "gzip", "bzip2", "xz"], received: "%s"`, compress)
	}
	defer w.Close()

	if _, err := w.Write(bs); err != nil {
		return errors.Wrap(err, "write data")
	}

	return nil
}
