package oval

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://ftp.suse.com/pub/projects/security/oval/"

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        int
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

type waitOption int

func (w waitOption) apply(opts *options) {
	opts.wait = int(w)
}

func WithWait(wait int) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "suse", "oval"),
		retry:       3,
		concurrency: 3,
		wait:        1,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch SUSE OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	us := make([]string, 0, len(ovals))
	for _, oval := range ovals {
		u, err := url.JoinPath(options.baseURL, oval)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}
		us = append(us, u)
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(us, options.concurrency, options.wait, func(resp *http.Response) error {
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		oval := path.Base(resp.Request.URL.Path)

		var osname, version string
		switch {
		case strings.HasPrefix(oval, "suse.linux.enterprise.desktop"):
			osname = "suse.linux.enterprise.desktop"
			version = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(oval, ".xml.gz"), "-affected"), "suse.linux.enterprise.desktop.")
		case strings.HasPrefix(oval, "suse.linux.enterprise.server"):
			osname = "suse.linux.enterprise.server"
			version = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(oval, ".xml.gz"), "-affected"), "suse.linux.enterprise.server.")
		case strings.HasPrefix(oval, "suse.linux.enterprise.micro"):
			osname = "suse.linux.enterprise.micro"
			version = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(oval, ".xml.gz"), "-affected"), "suse.linux.enterprise.micro.")
		case strings.HasPrefix(oval, "opensuse.leap"):
			osname = "opensuse.leap"
			if strings.HasPrefix(oval, "opensuse.leap.micro") {
				osname = "opensuse.leap.micro"
			}
			version = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(oval, ".xml.gz"), "-affected"), fmt.Sprintf("%s.", osname))
		case strings.HasPrefix(oval, "opensuse"):
			osname = "opensuse"
			version = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(oval, ".xml.gz"), "-affected"), "opensuse.")
		default:
			return errors.Wrapf(err, `unexpected ovalname. accepts: "<osname>.<version>.xml.gz", received: "%s"`, oval)
		}

		r, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "open oval as gzip")
		}
		defer r.Close() //nolint:errcheck

		var root root
		if err := xml.NewDecoder(r).Decode(&root); err != nil {
			return errors.Wrap(err, "decode oval")
		}

		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, osname, version, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
		}

		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, osname, version, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}

		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, osname, version, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
		}

		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, osname, version, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	ovals := make(map[string]string)
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasSuffix(txt, ".xml.gz") {
			return
		}
		if !strings.HasPrefix(txt, "opensuse") &&
			!strings.HasPrefix(txt, "opensuse.leap") &&
			!strings.HasPrefix(txt, "opensuse.leap.micro") &&
			!strings.HasPrefix(txt, "opensuse.tumbleweed") &&
			!strings.HasPrefix(txt, "suse.linux.enterprise.desktop") &&
			!strings.HasPrefix(txt, "suse.linux.enterprise.server") &&
			!strings.HasPrefix(txt, "suse.linux.enterprise.micro") {
			return
		}

		switch {
		case strings.Contains(txt, "-affected"):
			ovals[strings.TrimSuffix(txt, "-affected.xml.gz")] = txt
		case strings.Contains(txt, "-patch"):
		default:
			if _, ok := ovals[strings.TrimSuffix(txt, ".xml.gz")]; !ok {
				ovals[strings.TrimSuffix(txt, ".xml.gz")] = txt
			}
		}
	})
	return slices.Collect(maps.Values(ovals)), nil
}
