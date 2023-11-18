package v2

import (
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const feedURL = "https://www.redhat.com/security/data/oval/v2/feed.json"

type options struct {
	feedURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type feedURLOption string

func (u feedURLOption) apply(opts *options) {
	opts.feedURL = string(u)
}

func WithFeedURL(u string) Option {
	return feedURLOption(u)
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
		feedURL: feedURL,
		dir:     filepath.Join(util.CacheDir(), "redhat", "oval", "v2"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch RedHat OVAL")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.feedURL)
	if err != nil {
		return errors.Wrap(err, "fetch feed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error request response with status code %d", resp.StatusCode)
	}

	var f feed
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		return errors.Wrap(err, "decode json")
	}

	var urls []string
	for _, e := range f.Feed.Entry {
		urls = append(urls, e.Content.Src)
	}

	for _, u := range urls {
		d, file := path.Split(u)
		name := strings.TrimSuffix(file, ".oval.xml.bz2")
		v := strings.TrimPrefix(path.Base(path.Clean(d)), "RHEL")

		log.Printf("[INFO] Fetch RedHat %s %s OVAL", v, name)
		r, err := func() (*root, error) {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch advisory")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error request response with status code %d", resp.StatusCode)
			}

			var root root
			if err := xml.NewDecoder(bzip2.NewReader(resp.Body)).Decode(&root); err != nil {
				return nil, errors.Wrap(err, "decode xml")
			}

			return &root, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		log.Printf("[INFO] Fetch RedHat %s %s Definitions", v, name)
		bar := pb.StartNew(len(r.Definitions.Definition))
		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, v, name, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s Tests", v, name)
		bar = pb.StartNew(len(r.Tests.RpminfoTest) + len(r.Tests.RpmverifyfileTest) + len(r.Tests.Textfilecontent54Test) + len(r.Tests.UnameTest))
		for _, test := range r.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range r.Tests.RpmverifyfileTest {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range r.Tests.UnameTest {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s Objects", v, name)
		bar = pb.StartNew(len(r.Objects.RpminfoObject) + 1 + len(r.Objects.Textfilecontent54Object) + 1)
		for _, object := range r.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		if r.Objects.RpmverifyfileObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", r.Objects.RpmverifyfileObject.ID)), r.Objects.RpmverifyfileObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", r.Objects.RpmverifyfileObject.ID)))
			}
		}
		bar.Increment()
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		if r.Objects.UnameObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "uname_object", fmt.Sprintf("%s.json", r.Objects.UnameObject.ID)), r.Objects.UnameObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "uname_object", fmt.Sprintf("%s.json", r.Objects.UnameObject.ID)))
			}
		}
		bar.Increment()
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s States", v, name)
		bar = pb.StartNew(len(r.States.RpminfoState) + len(r.States.RpmverifyfileState) + len(r.States.Textfilecontent54State) + len(r.States.UnameState))
		for _, state := range r.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range r.States.RpmverifyfileState {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range r.States.UnameState {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s Variables", v, name)
		bar = pb.StartNew(1)
		if r.Variables.LocalVariable.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, name, "variables", "local_variable", fmt.Sprintf("%s.json", r.Variables.LocalVariable.ID)), r.Variables.LocalVariable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "variables", "local_variable", fmt.Sprintf("%s.json", r.Variables.LocalVariable.ID)))
			}
		}
		bar.Increment()
		bar.Finish()

	}

	return nil
}
