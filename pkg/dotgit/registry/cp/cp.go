package cp

import (
	"context"

	"github.com/pkg/errors"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

type options struct {
	force bool
}

type Option interface {
	apply(*options)
}

type forceOption bool

func (f forceOption) apply(opts *options) {
	opts.force = bool(f)
}

func WithForce(force bool) Option {
	return forceOption(force)
}

func Copy(from, to, token string, opts ...Option) error {
	options := &options{
		force: false,
	}

	for _, opt := range opts {
		opt.apply(options)
	}

	ctx := context.TODO()

	fr, err := remote.NewRepository(from)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", from)
	}
	if fr.Reference.Reference == "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, from)
	}

	tr, err := remote.NewRepository(to)
	if err != nil {
		return errors.Wrapf(err, "create client for %s", to)
	}
	if tr.Reference.Reference == "" {
		return errors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>:<tag>"}, to)
	}

	tr.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(tr.Reference.Host(), auth.Credential{
			Username: "user", // Any string but empty
			Password: token,
		}),
	}

	if !options.force {
		_, err := tr.Resolve(ctx, tr.Reference.Reference)
		if err == nil {
			return errors.Errorf("tag %q already exists in %q", tr.Reference.Reference, tr.Reference.Repository)
		}
		if !errors.Is(err, errdef.ErrNotFound) {
			return errors.Wrap(err, "check existing tags")
		}
	}

	if _, err := oras.Copy(ctx, fr, fr.Reference.Reference, tr, tr.Reference.Reference, oras.DefaultCopyOptions); err != nil {
		return errors.Wrapf(err, "copy from %q to %q", from, to)
	}

	return nil
}
