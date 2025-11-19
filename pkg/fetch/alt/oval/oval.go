package oval

import (
	"archive/zip"
	"bytes"
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://rdb.altlinux.org/api/errata/export/oval/"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "alt", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch ALT Linux OVAL")
	bs, err := options.fetchBranches()
	if err != nil {
		return errors.Wrap(err, "fetch branches")
	}

	for _, b := range bs {
		log.Printf("[INFO] Fetch ALT Linux %s OVAL", b)
		if err := options.fetch(b); err != nil {
			return errors.Wrapf(err, "fetch alt linux %s oval", b)
		}
	}

	return nil
}

func (opts options) fetchBranches() ([]string, error) {
	u, err := url.JoinPath(opts.baseURL, "branches")
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return nil, errors.Wrap(err, "fetch branches")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var bs branches
	if err := json.UnmarshalRead(resp.Body, &bs); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	return bs.Branches, nil
}

func (opts options) fetch(branch string) error {
	u, err := url.JoinPath(opts.baseURL, branch)
	if err != nil {
		return errors.Wrap(err, "join url path")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "read all response body")
	}

	zr, err := zip.NewReader(bytes.NewReader(bs), int64(len(bs)))
	if err != nil {
		return errors.Wrap(err, "create zip reader")
	}

	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || filepath.Ext(zf.Name) != ".xml" {
			continue
		}

		r, err := func() (*root, error) {
			f, err := zf.Open()
			if err != nil {
				return nil, errors.Wrapf(err, "open %s", zf.Name)
			}
			defer f.Close()

			var r root
			if err := xml.NewDecoder(f).Decode(&r); err != nil {
				return nil, errors.Wrap(err, "decode xml")
			}

			return &r, nil
		}()
		if err != nil {
			return errors.Wrapf(err, "read %s", zf.Name)
		}

		name := strings.TrimSuffix(filepath.Base(zf.Name), ".xml")

		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(opts.dir, branch, name, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, branch, name, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
		}

		for _, test := range r.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(opts.dir, branch, name, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, branch, name, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(opts.dir, branch, name, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, branch, name, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}

		for _, object := range r.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(opts.dir, branch, name, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, branch, name, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
		}
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(opts.dir, branch, name, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, branch, name, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
		}

		for _, state := range r.States.RpminfoState {
			if err := util.Write(filepath.Join(opts.dir, branch, name, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, branch, name, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
		}
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(opts.dir, branch, name, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, branch, name, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
		}
	}

	return nil
}
