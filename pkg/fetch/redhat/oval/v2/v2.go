package v2

import (
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
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
	bs, err := utilhttp.Get(options.feedURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch feed")
	}

	var f feed
	if err := json.Unmarshal(bs, &f); err != nil {
		return errors.Wrap(err, "unmarshal json")
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
		bs, err := utilhttp.Get(u, options.retry)
		if err != nil {
			return errors.Wrap(err, "fetch advisory")
		}

		var root root
		if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
			return errors.Wrap(err, "unmarshal advisory")
		}

		log.Printf("[INFO] Fetch RedHat %s %s Definitions", v, name)
		bar := pb.StartNew(len(root.Definitions.Definition))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, v, name, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s Tests", v, name)
		bar = pb.StartNew(len(root.Tests.RpminfoTest) + len(root.Tests.RpmverifyfileTest) + len(root.Tests.Textfilecontent54Test) + len(root.Tests.UnameTest))
		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range root.Tests.RpmverifyfileTest {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range root.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range root.Tests.UnameTest {
			if err := util.Write(filepath.Join(options.dir, v, name, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s Objects", v, name)
		bar = pb.StartNew(len(root.Objects.RpminfoObject) + 1 + len(root.Objects.Textfilecontent54Object) + 1)
		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		if root.Objects.RpmverifyfileObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", root.Objects.RpmverifyfileObject.ID)), root.Objects.RpmverifyfileObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", root.Objects.RpmverifyfileObject.ID)))
			}
		}
		bar.Increment()
		for _, object := range root.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		if root.Objects.UnameObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, name, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)), root.Objects.UnameObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)))
			}
		}
		bar.Increment()
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s States", v, name)
		bar = pb.StartNew(len(root.States.RpminfoState) + len(root.States.RpmverifyfileState) + len(root.States.Textfilecontent54State) + len(root.States.UnameState))
		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range root.States.RpmverifyfileState {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range root.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range root.States.UnameState {
			if err := util.Write(filepath.Join(options.dir, v, name, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s %s Variables", v, name)
		bar = pb.StartNew(1)
		if root.Variables.LocalVariable.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, name, "variables", "local_variable", fmt.Sprintf("%s.json", root.Variables.LocalVariable.ID)), root.Variables.LocalVariable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, name, "variables", "local_variable", fmt.Sprintf("%s.json", root.Variables.LocalVariable.ID)))
			}
		}
		bar.Increment()
		bar.Finish()

	}

	return nil
}
