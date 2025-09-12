package olam

import (
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://linux.oracle.com/security/oval/com.oracle.olamsa-all.xml.bz2"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithBaseURL(url string) Option {
	return baseURLOption(url)
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
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "oracle", "olam"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Oracle Linux Automation Manager")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.baseURL)
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

	log.Printf("[INFO] Fetch Oracle Linux Automation Manager Definitions")
	bar := pb.StartNew(len(root.Definitions.Definition))
	for _, def := range root.Definitions.Definition {
		if err := util.Write(filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "definitions", fmt.Sprintf("%s.json", def.ID)))
		}
		bar.Increment()
	}
	bar.Finish()

	log.Printf("[INFO] Fetch Oracle Linux Automation Manager Tests")
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

	log.Printf("[INFO] Fetch Oracle Linux Automation Manager Objects")
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

	log.Printf("[INFO] Fetch Oracle Linux Automation Manager States")
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
