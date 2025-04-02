package pull

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

type options struct {
	dir     string
	restore bool
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

type restoreOption bool

func (r restoreOption) apply(opts *options) {
	opts.restore = bool(r)
}

func WithRestore(restore bool) Option {
	return restoreOption(restore)
}

func Pull(repository string, opts ...Option) error {
	options := &options{
		dir:     filepath.Join(util.CacheDir(), "dotgit"),
		restore: false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	log.Printf("[INFO] Pull dotgit from %s", repository)

	ctx := context.TODO()

	repo, err := remote.NewRepository(repository)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", repository)
	}
	if repo.Reference.Reference == "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, repository)
	}

	if err := os.RemoveAll(filepath.Join(options.dir, repo.Reference.Reference)); err != nil {
		return errors.Wrapf(err, "remove %s", filepath.Join(options.dir, repo.Reference.Reference))
	}

	_, r, err := oras.Fetch(ctx, repo, repo.Reference.Reference, oras.DefaultFetchOptions)
	if err != nil {
		return errors.Wrap(err, "fetch manifest")
	}
	defer r.Close() //nolint:errcheck

	var manifest ocispec.Manifest
	if err := json.NewDecoder(r).Decode(&manifest); err != nil {
		return errors.Wrap(err, "decode manifest")
	}

	l := func() *ocispec.Descriptor {
		for _, l := range manifest.Layers {
			if l.MediaType == "application/vnd.vulsio.vuls-data-db.dotgit.layer.v1.tar+zstd" {
				return &l
			}
		}
		return nil
	}()
	if l == nil {
		return errors.Errorf("not found digest and filename from layers, actual layers: %#v", manifest.Layers)
	}

	r, err = repo.Fetch(ctx, *l)
	if err != nil {
		return errors.Wrap(err, "fetch content")
	}
	defer r.Close() //nolint:errcheck

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

		p := filepath.Join(options.dir, hdr.Name)

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

	if options.restore {
		cmd := exec.Command("git", "-C", filepath.Join(options.dir, repo.Reference.Reference), "restore", ".")
		if err := cmd.Run(); err != nil {
			return errors.Wrapf(err, "exec %q", cmd.String())
		}
	}

	return nil
}
