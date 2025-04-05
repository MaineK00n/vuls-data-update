package compress

import (
	"archive/tar"
	stderrors "errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
)

type options struct {
	root string

	level int
}

type Option interface {
	apply(*options)
}

type rootOption string

func (r rootOption) apply(opts *options) {
	opts.root = string(r)
}

func WithRoot(root string) Option {
	return rootOption(root)
}

type levelOption int

func (l levelOption) apply(opts *options) {
	opts.level = int(l)
}

func WithLevel(level int) Option {
	return levelOption(level)
}

func Compress(src, dst string, opts ...Option) error {
	options := &options{
		root: func() string {
			p, err := filepath.Abs(src)
			if err != nil {
				return filepath.Base(src)
			}
			return filepath.Base(p)
		}(),

		level: 3,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	log.Printf("[INFO] Compress %s dotgit to %s", src, dst)

	if err := options.compress(src, dst); err != nil {
		if err2 := os.Remove(dst); err2 != nil {
			err = stderrors.Join(err, errors.Wrapf(err2, "remove %s", dst))
		}
		return errors.Wrapf(err, "compress %s to %s", src, dst)
	}
	return nil
}

func (o options) compress(src, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return errors.Wrapf(err, "create %s", dst)
	}
	defer f.Close() //nolint:errcheck

	zw, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(o.level)))
	if err != nil {
		return errors.Wrap(err, "new zstd writer")
	}
	defer zw.Close() //nolint:errcheck

	tw := tar.NewWriter(zw)
	defer tw.Close() //nolint:errcheck

	info, err := os.Stat(src)
	if err != nil {
		return errors.Wrapf(err, "stat %s", src)
	}
	hdr, err := tar.FileInfoHeader(info, src)
	if err != nil {
		return errors.Wrapf(err, "file info header %s", src)
	}
	hdr.Name = fmt.Sprintf("%s/", o.root)

	if err := tw.WriteHeader(hdr); err != nil {
		return errors.Wrapf(err, "write header %s", src)
	}

	if err := filepath.WalkDir(filepath.Join(src, ".git"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return errors.Wrapf(err, "get info %s", path)
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return errors.Wrapf(err, "relative filepath. prefix: %q, path: %q", src, path)
		}

		hdr, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return errors.Wrapf(err, "file info header %s", path)
		}

		switch {
		case d.IsDir():
			hdr.Name = fmt.Sprintf("%s/", filepath.Join(o.root, rel))

			if err := tw.WriteHeader(hdr); err != nil {
				return errors.Wrapf(err, "write header %#v", hdr)
			}

			return nil
		default:
			hdr.Name = filepath.Join(o.root, rel)

			if err := tw.WriteHeader(hdr); err != nil {
				return errors.Wrapf(err, "write header %#v", hdr)
			}

			f, err := os.Open(path)
			if err != nil {
				return errors.Wrapf(err, "open %s", path)
			}
			defer f.Close() //nolint:errcheck

			if _, err := io.Copy(tw, f); err != nil {
				return errors.Wrapf(err, "copy %s", path)
			}

			return nil
		}
	}); err != nil {
		return errors.Wrapf(err, "walk %s", src)
	}

	return nil
}
