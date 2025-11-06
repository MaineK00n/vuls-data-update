package openstack

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://linux.oracle.com/oval/"

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "oracle", "openstack"),
		retry:       3,
		concurrency: 3,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Oracle Linux OpenStack")
	if err := options.fetch(); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (opts options) fetch() error {
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))

	resp, err := client.Get(opts.baseURL)
	if err != nil {
		return errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "parse as html")
	}

	var as []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "com.oracle.olossa-") {
			return
		}
		as = append(as, txt)
	})

	us := make([]string, 0, len(as))
	for _, a := range as {
		u, err := url.JoinPath(opts.baseURL, a)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}
		us = append(us, u)
	}

	bar := pb.StartNew(len(us))
	if err := client.PipelineGet(us, opts.concurrency, opts.wait, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		var root root
		if err := xml.NewDecoder(resp.Body).Decode(&root); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(opts.dir, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
		}
		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(opts.dir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}
		for _, test := range root.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(opts.dir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}

		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(opts.dir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
		}
		for _, object := range root.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(opts.dir, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
		}

		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(opts.dir, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "states", "", fmt.Sprintf("%s.json", state.ID)))
			}
		}
		for _, state := range root.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(opts.dir, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "states", "", fmt.Sprintf("%s.json", state.ID)))
			}
		}

		bar.Increment()

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}
	bar.Finish()

	return nil
}
