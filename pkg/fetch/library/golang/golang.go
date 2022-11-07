package golang

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/golang/db"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/golang/ghsa"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/golang/glsa"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/golang/govulndb"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/golang/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type options struct {
	dir            string
	retry          int
	compressFormat string
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

type retryOption int

func (r retryOption) apply(opts *options) {
	opts.retry = int(r)
}

func WithRetry(retry int) Option {
	return retryOption(retry)
}

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		dir:   filepath.Join(util.SourceDir(), "golang"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := db.Fetch(db.WithDir(filepath.Join(options.dir, "db")), db.WithRetry(options.retry), db.WithCompressFormat(options.compressFormat)); err != nil {
		return errors.Wrap(err, "fetch golang db")
	}

	if err := ghsa.Fetch(ghsa.WithDir(filepath.Join(options.dir, "ghsa")), ghsa.WithRetry(options.retry), ghsa.WithCompressFormat(options.compressFormat)); err != nil {
		return errors.Wrap(err, "fetch golang ghsa")
	}

	if err := glsa.Fetch(glsa.WithDir(filepath.Join(options.dir, "glsa")), glsa.WithRetry(options.retry), glsa.WithCompressFormat(options.compressFormat)); err != nil {
		return errors.Wrap(err, "fetch golang glsa")
	}

	if err := govulndb.Fetch(govulndb.WithDir(filepath.Join(options.dir, "go-vulndb")), govulndb.WithRetry(options.retry), govulndb.WithCompressFormat(options.compressFormat)); err != nil {
		return errors.Wrap(err, "fetch golang govulndb")
	}

	if err := osv.Fetch(osv.WithDir(filepath.Join(options.dir, "osv")), osv.WithRetry(options.retry), osv.WithCompressFormat(options.compressFormat)); err != nil {
		return errors.Wrap(err, "fetch golang osv")
	}

	return nil
}
