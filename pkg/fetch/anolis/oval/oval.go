package oval

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://anas.openanolis.cn/api/data/OVAL/"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "anolis", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Anolis OS OVAL")
	ovals, err := options.fetchList()
	if err != nil {
		return errors.Wrap(err, "fetch list")
	}

	for _, ovalname := range ovals {
		ver := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".oval.xml"), "anolis-")

		log.Printf("[INFO] Fetch Anolis OS %s OVAL", ver)
		root, err := options.fetch(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch anolis %s oval", ver)
		}

		log.Printf("[INFO] Fetch Anolis OS %s Definitions", ver)
		bar := pb.StartNew(len(root.Definitions.Definition))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Anolis OS %s Tests", ver)
		bar = pb.StartNew(len(root.Tests.RpminfoTest) + len(root.Tests.Textfilecontent54Test))
		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		for _, test := range root.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, ver, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Anolis OS %s Objects", ver)
		bar = pb.StartNew(len(root.Objects.RpminfoObject) + len(root.Objects.Textfilecontent54Object))
		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		for _, object := range root.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, ver, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Anolis OS %s States", ver)
		bar = pb.StartNew(len(root.States.RpminfoState) + len(root.States.Textfilecontent54State))
		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		for _, state := range root.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, ver, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (opts options) fetchList() ([]string, error) {
	u, err := url.Parse(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "parse url")
	}
	q := u.Query()
	q.Set("format", "json")
	u.RawQuery = q.Encode()

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(u.String())
	if err != nil {
		return nil, errors.Wrap(err, "fetch list")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var l list
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return nil, errors.Wrap(err, "decode json")
	}

	fs := make([]string, 0, len(l.Data.Data))
	for _, d := range l.Data.Data {
		fs = append(fs, d.Name)
	}

	return fs, nil
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
	if err := xml.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, errors.Wrap(err, "decode xml")
	}

	return &r, nil
}
