package oval

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "suse", "oval"),
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

	log.Println("[INFO] Fetch SUSE OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	us := make([]string, 0, len(ovals))
	fnByURL := make(map[string]FileName, len(ovals))
	for _, fn := range ovals {
		fullURL, err := url.JoinPath(options.baseURL, fn.Raw)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}

		us = append(us, fullURL)
		fnByURL[fullURL] = fn
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(us, options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("unexpected error response. expected: %d, actual: %d", http.StatusOK, resp.StatusCode)
		}

		fn, ok := fnByURL[resp.Request.URL.String()]
		if !ok {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("unexpected response url: %s", resp.Request.URL.String())
		}
		ovaltype := fn.OvalType()
		osname := fn.OS
		version := fn.Version

		r, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "open oval as gzip")
		}
		defer r.Close()

		var root root
		if err := xml.NewDecoder(r).Decode(&root); err != nil {
			return errors.Wrap(err, "decode oval")
		}

		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, osname, version, ovaltype, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, ovaltype, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
		}

		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, osname, version, ovaltype, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, ovaltype, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}
		for _, test := range root.Tests.UnameTest {
			if err := util.Write(filepath.Join(options.dir, osname, version, ovaltype, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, ovaltype, "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}

		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, osname, version, ovaltype, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, ovaltype, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
		}
		if root.Objects.UnameObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, osname, version, ovaltype, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)), root.Objects.UnameObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, ovaltype, "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)))
			}
		}

		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, osname, version, ovaltype, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, ovaltype, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
		}
		for _, state := range root.States.UnameState {
			if err := util.Write(filepath.Join(options.dir, osname, version, ovaltype, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, osname, version, ovaltype, "states", "uname_state", fmt.Sprintf("%s.json", state.ID)))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

func (opts options) walkIndexOf() ([]FileName, error) {
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

	grouped, err := collectOVALFiles(d)
	if err != nil {
		return nil, errors.Wrap(err, "collect oval files")
	}

	fns := make([]FileName, 0, len(grouped)*2)
	for _, variants := range grouped {
		if fn, ok := variants[VariantAffected]; ok {
			fns = append(fns, fn)
		} else if fn, ok := variants[VariantNone]; ok {
			fns = append(fns, fn)
		}
		if fn, ok := variants[VariantPatch]; ok {
			fns = append(fns, fn)
		}
	}
	return fns, nil
}

// collectOVALFiles parses HTML and groups filenames by OS/Version and Variant.
func collectOVALFiles(d *goquery.Document) (map[FileKey]map[Variant]FileName, error) {
	grouped := make(map[FileKey]map[Variant]FileName)
	var parseErr error
	d.Find("a").EachWithBreak(func(_ int, selection *goquery.Selection) bool {
		href, ok := selection.Attr("href")
		if !ok {
			return true
		}
		if strings.HasSuffix(href, "/") || href == "../" {
			return true
		}
		if !strings.HasSuffix(href, ".xml.gz") {
			return true
		}

		fn, err := ParseFileName(path.Base(href))
		if err != nil {
			parseErr = errors.Wrapf(err, "parse filename: %s", href)
			return false
		}

		if fn == nil {
			return true
		}
		if !fn.ShouldInclude() {
			return true
		}

		key := fn.Key()
		if grouped[key] == nil {
			grouped[key] = make(map[Variant]FileName)
		}
		grouped[key][fn.Variant] = *fn
		return true
	})
	if parseErr != nil {
		return nil, parseErr
	}
	return grouped, nil
}
