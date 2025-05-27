package v1

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://security.access.redhat.com/data/archive/oval_v1_20230706.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "redhat", "oval", "v1"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch RedHat OVALv1")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch archive ovalv1")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "open archive as gzip")
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if !strings.HasPrefix(filepath.Base(hdr.Name), "com.redhat.rhsa-RHEL") {
			continue
		}

		v := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(hdr.Name), "com.redhat.rhsa-RHEL"), ".xml")

		var root root
		if err := xml.NewDecoder(tr).Decode(&root); err != nil {
			return errors.Wrap(err, "decode oval")
		}

		log.Printf("[INFO] Fetch RedHat %s Definitions", v)
		bar := pb.StartNew(len(root.Definitions.Definition))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, v, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s Tests", v)
		bar = pb.StartNew(len(root.Tests.RpminfoTest) + len(root.Tests.UnameTest) + len(root.Tests.Textfilecontent54Test) + len(root.Tests.RpmverifyfileTest))
		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, v, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range root.Tests.UnameTest {
			if err := util.Write(filepath.Join(options.dir, v, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range root.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, v, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range root.Tests.RpmverifyfileTest {
			if err := util.Write(filepath.Join(options.dir, v, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s Objects", v)
		bar = pb.StartNew(len(root.Objects.RpminfoObject) + 1 + len(root.Objects.Textfilecontent54Object) + 1)
		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, v, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		if root.Objects.UnameObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)), root.Objects.UnameObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)))
			}
		}
		bar.Increment()
		for _, object := range root.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, v, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		if root.Objects.RpmverifyfileObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", root.Objects.RpmverifyfileObject.ID)), root.Objects.RpmverifyfileObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", root.Objects.RpmverifyfileObject.ID)))
			}
		}
		bar.Increment()
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s States", v)
		bar = pb.StartNew(len(root.States.RpminfoState) + len(root.States.UnameState) + len(root.States.Textfilecontent54State) + len(root.States.RpmverifyfileState))
		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, v, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range root.States.UnameState {
			if err := util.Write(filepath.Join(options.dir, v, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range root.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, v, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range root.States.RpmverifyfileState {
			if err := util.Write(filepath.Join(options.dir, v, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch RedHat %s Variables", v)
		bar = pb.StartNew(1)
		if root.Variables.LocalVariable.ID != "" {
			if err := util.Write(filepath.Join(options.dir, v, "variables", "local_variable", fmt.Sprintf("%s.json", root.Variables.LocalVariable.ID)), root.Variables.LocalVariable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, "variables", "local_variable", fmt.Sprintf("%s.json", root.Variables.LocalVariable.ID)))
			}
		}
		bar.Increment()
		bar.Finish()
	}

	return nil
}
