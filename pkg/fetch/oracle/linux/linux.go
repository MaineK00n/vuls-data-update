package linux

import (
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
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
		dir:         filepath.Join(util.CacheDir(), "fetch", "oracle", "linux"),
		retry:       3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Oracle Linux")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.advisoryURL)
	if err != nil {
		return errors.Wrap(err, "fetch advisory")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var root root
	if err := xml.NewDecoder(bzip2.NewReader(resp.Body)).Decode(&root); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	log.Printf("[INFO] Fetch Oracle Linux Definitions")
	bar := progressbar.Default(int64(len(root.Definitions.Definition)))
	for _, def := range root.Definitions.Definition {
		if err := util.Write(filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json", def.ID)))
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	log.Printf("[INFO] Fetch Oracle Linux Tests")
	bar = progressbar.Default(int64(len(root.Tests.RpminfoTest) + len(root.Tests.Textfilecontent54Test)))
	for _, test := range root.Tests.RpminfoTest {
		if err := util.Write(filepath.Join(options.dir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
		}
		_ = bar.Add(1)
	}
	for _, test := range root.Tests.Textfilecontent54Test {
		if err := util.Write(filepath.Join(options.dir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	log.Printf("[INFO] Fetch Oracle Linux Objects")
	bar = progressbar.Default(int64(len(root.Objects.RpminfoObject) + len(root.Objects.Textfilecontent54Object)))
	for _, object := range root.Objects.RpminfoObject {
		if err := util.Write(filepath.Join(options.dir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
		}
		_ = bar.Add(1)
	}
	for _, object := range root.Objects.Textfilecontent54Object {
		if err := util.Write(filepath.Join(options.dir, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	log.Printf("[INFO] Fetch Oracle Linux States")
	bar = progressbar.Default(int64(len(root.States.RpminfoState) + len(root.States.Textfilecontent54State)))
	for _, state := range root.States.RpminfoState {
		if err := util.Write(filepath.Join(options.dir, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
		}
		_ = bar.Add(1)
	}
	for _, state := range root.States.Textfilecontent54State {
		if err := util.Write(filepath.Join(options.dir, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
