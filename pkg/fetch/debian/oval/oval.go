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

const baseURL = "https://www.debian.org/security/oval/"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "debian", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Debian OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		code := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.bz2"), "oval-definitions-")

		log.Printf("[INFO] Fetch Debian %s OVAL", code)
		root, err := options.fetch(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch debian %s oval", code)
		}

		log.Printf("[INFO] Fetch Debian %s Definitions", code)
		bar := progressbar.Default(int64(len(root.Definitions.Definition)))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, code, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		log.Printf("[INFO] Fetch Debian %s Tests", code)
		bar = progressbar.Default(2 + int64(len(root.Tests.DpkginfoTest)))
		if err := util.Write(filepath.Join(options.dir, code, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", root.Tests.Textfilecontent54Test.ID)), root.Tests.Textfilecontent54Test); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", root.Tests.Textfilecontent54Test.ID)))
		}
		_ = bar.Add(1)
		if err := util.Write(filepath.Join(options.dir, code, "tests", "uname_test", fmt.Sprintf("%s.json", root.Tests.UnameTest.ID)), root.Tests.UnameTest); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "tests", "uname_test", fmt.Sprintf("%s.json", root.Tests.UnameTest.ID)))
		}
		_ = bar.Add(1)
		for _, test := range root.Tests.DpkginfoTest {
			if err := util.Write(filepath.Join(options.dir, code, "tests", "dpkginfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "tests", "dpkginfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		log.Printf("[INFO] Fetch Debian %s Objects", code)
		bar = progressbar.Default(2 + int64(len(root.Objects.DpkginfoObject)))
		if err := util.Write(filepath.Join(options.dir, code, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", root.Objects.Textfilecontent54Object.ID)), root.Objects.Textfilecontent54Object); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", root.Objects.Textfilecontent54Object.ID)))
		}
		_ = bar.Add(1)
		if err := util.Write(filepath.Join(options.dir, code, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)), root.Objects.UnameObject); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)))
		}
		_ = bar.Add(1)
		for _, object := range root.Objects.DpkginfoObject {
			if err := util.Write(filepath.Join(options.dir, code, "objects", "dpkginfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "objects", "dpkginfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		log.Printf("[INFO] Fetch Debian %s States", code)
		bar = progressbar.Default(1 + int64(len(root.States.DpkginfoState)))
		if root.States.Textfilecontent54State.ID != "" {
			if err := util.Write(filepath.Join(options.dir, code, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", root.States.Textfilecontent54State.ID)), root.States.Textfilecontent54State); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", root.States.Textfilecontent54State.ID)))
			}
		}
		_ = bar.Add(1)
		for _, state := range root.States.DpkginfoState {
			if err := util.Write(filepath.Join(options.dir, code, "states", "dpkginfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, code, "states", "dpkginfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
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
		if !strings.HasPrefix(txt, "oval-definitions-") {
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
