package oval

import (
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/html/charset"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://security.almalinux.org/oval/"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "alma", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch AlmaLinux OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		ver := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.bz2"), "org.almalinux.alsa-")

		log.Printf("[INFO] Fetch AlmaLinux %s OVAL", ver)
		root, err := options.fetch(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch alma %s oval", ver)
		}

		log.Printf("[INFO] Fetch AlmaLinux %s Definitions", ver)
		bar := progressbar.Default(int64(len(root.Definitions.Definition)))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		log.Printf("[INFO] Fetch AlmaLinux %s Tests", ver)
		bar = progressbar.Default(int64(len(root.Tests.RpminfoTest) + len(root.Tests.RpmverifyfileTest) + len(root.Tests.Textfilecontent54Test) + len(root.Tests.UnameTest)))
		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		for _, test := range root.Tests.RpmverifyfileTest {
			if err := util.Write(filepath.Join(options.dir, ver, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "tests", "rpmverifyfile_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		for _, test := range root.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, ver, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		for _, test := range root.Tests.UnameTest {
			if err := util.Write(filepath.Join(options.dir, ver, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		log.Printf("[INFO] Fetch AlmaLinux %s Objects", ver)
		bar = progressbar.Default(int64(len(root.Objects.RpminfoObject) + len(root.Objects.RpmverifyfileObject) + len(root.Objects.Textfilecontent54Object) + 1))
		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			_ = bar.Add(1)
		}
		for _, object := range root.Objects.RpmverifyfileObject {
			if err := util.Write(filepath.Join(options.dir, ver, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "objects", "rpmverifyfile_object", fmt.Sprintf("%s.json", object.ID)))
			}
			_ = bar.Add(1)
		}
		for _, object := range root.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, ver, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			_ = bar.Add(1)
		}
		if root.Objects.UnameObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, ver, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)), root.Objects.UnameObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)))
			}
		}
		_ = bar.Add(1)
		_ = bar.Close()

		log.Printf("[INFO] Fetch AlmaLinux %s States", ver)
		bar = progressbar.Default(int64(len(root.States.RpminfoState) + len(root.States.RpmverifyfileState) + len(root.States.Textfilecontent54State) + len(root.States.UnameState)))
		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
		for _, state := range root.States.RpmverifyfileState {
			if err := util.Write(filepath.Join(options.dir, ver, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "states", "rpmverifyfile_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
		for _, state := range root.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, ver, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
		for _, state := range root.States.UnameState {
			if err := util.Write(filepath.Join(options.dir, ver, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		log.Printf("[INFO] Fetch AlmaLinux %s Variables", ver)
		bar = progressbar.Default(1)
		if root.Variables.LocalVariable.ID != "" {
			if err := util.Write(filepath.Join(options.dir, ver, "variables", "local_variable", fmt.Sprintf("%s.json", root.Variables.LocalVariable.ID)), root.Variables.LocalVariable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "variables", "local_variable", fmt.Sprintf("%s.json", root.Variables.LocalVariable.ID)))
			}
		}
		_ = bar.Add(1)
		_ = bar.Close()
	}

	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var ovals []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasSuffix(txt, ".xml.bz2") {
			return
		}
		ovals = append(ovals, txt)
	})
	return ovals, nil
}

func (opts options) fetch(ovalname string) (*root, error) {
	u, err := url.JoinPath(opts.baseURL, ovalname)
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r root
	d := xml.NewDecoder(bzip2.NewReader(resp.Body))
	d.CharsetReader = charset.NewReaderLabel

	if err := d.Decode(&r); err != nil {
		return nil, errors.Wrap(err, "decode xml")
	}

	return &r, nil
}
