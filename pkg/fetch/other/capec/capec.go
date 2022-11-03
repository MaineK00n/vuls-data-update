package capec

import (
	"encoding/json"
	"log"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

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
		dir:     filepath.Join(util.SourceDir(), "capec"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch Common Attack Pattern Enumerations and Classifications")
	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch capec data")
	}

	var capec interface{}
	if err := json.Unmarshal(bs, &capec); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	return nil
}
