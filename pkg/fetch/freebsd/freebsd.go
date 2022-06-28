package freebsd

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://vuxml.freebsd.org/freebsd/vuln.xml.bz2"

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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

func Fetch(opts ...Option) error {
	options := &options{
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "freebsd"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch FreeBSD")
	bs, err := utilhttp.Get(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}

	var vuxml vuxml
	if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&vuxml); err != nil {
		return errors.Wrap(err, "decode advisory")
	}

	bar := pb.StartNew(len(vuxml.Vuln))
	for _, v := range vuxml.Vuln {
		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json", v.Vid)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json", v.Vid)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
