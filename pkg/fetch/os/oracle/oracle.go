package oracle

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const advisoryURL = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"

type options struct {
	advisoryURL string
	dir         string
	retry       int
}

type Option interface {
	apply(*options)
}

type advisoryURLOption string

func (a advisoryURLOption) apply(opts *options) {
	opts.advisoryURL = string(a)
}

func WithAdvisoryURL(advisoryURL string) Option {
	return advisoryURLOption(advisoryURL)
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
		advisoryURL: advisoryURL,
		dir:         filepath.Join(util.SourceDir(), "oracle"),
		retry:       3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Oracle Linux")
	bs, err := util.FetchURL(options.advisoryURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}

	var root root
	if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
		return errors.Wrap(err, "unmarshal advisory")
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}
	if err := os.MkdirAll(options.dir, os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", options.dir)
	}

	bar := pb.StartNew(len(root.Definitions.Definition) + 3)
	for _, def := range root.Definitions.Definition {
		if err := util.Write(filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json.gz", def.ID)), def); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json.gz", def.ID)))
		}
		bar.Increment()
	}

	if err := util.Write(filepath.Join(options.dir, "tests", "tests.json.gz"), root.Tests); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "tests", "tests.json.gz"))
	}
	bar.Increment()

	if err := util.Write(filepath.Join(options.dir, "objects", "objects.json.gz"), root.Objects); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "objects", "objects.json.gz"))
	}
	bar.Increment()

	if err := util.Write(filepath.Join(options.dir, "states", "states.json.gz"), root.States); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "states", "states.json.gz"))
	}
	bar.Increment()

	bar.Finish()

	return nil
}
