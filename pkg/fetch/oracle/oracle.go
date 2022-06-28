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

	log.Printf("[INFO] Fetch Oracle Linux Definitions")
	bar := pb.StartNew(len(root.Definitions.Definition))
	for _, def := range root.Definitions.Definition {
		if err := util.Write(filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json", def.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	log.Printf("[INFO] Fetch Oracle Linux Tests")
	bar = pb.StartNew(len(root.Tests.RpminfoTest) + len(root.Tests.Textfilecontent54Test))
	for _, test := range root.Tests.RpminfoTest {
		if err := util.Write(filepath.Join(options.dir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
		}
		bar.Increment()
	}
	for _, test := range root.Tests.Textfilecontent54Test {
		if err := util.Write(filepath.Join(options.dir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	log.Printf("[INFO] Fetch Oracle Linux Objects")
	bar = pb.StartNew(len(root.Objects.RpminfoObject) + len(root.Objects.Textfilecontent54Object))
	for _, object := range root.Objects.RpminfoObject {
		if err := util.Write(filepath.Join(options.dir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
		}
		bar.Increment()
	}
	for _, object := range root.Objects.Textfilecontent54Object {
		if err := util.Write(filepath.Join(options.dir, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	log.Printf("[INFO] Fetch Oracle Linux States")
	bar = pb.StartNew(len(root.States.RpminfoState) + len(root.States.Textfilecontent54State))
	for _, state := range root.States.RpminfoState {
		if err := util.Write(filepath.Join(options.dir, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "states", "", fmt.Sprintf("%s.json", state.ID)))
		}
		bar.Increment()
	}
	for _, state := range root.States.Textfilecontent54State {
		if err := util.Write(filepath.Join(options.dir, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "states", "", fmt.Sprintf("%s.json", state.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}
