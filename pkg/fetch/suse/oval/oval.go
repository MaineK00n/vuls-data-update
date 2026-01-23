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
	"path/filepath"
	"slices"
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

	m := make(map[string]ovalfile, len(ovals))
	for _, fn := range ovals {
		u, err := url.JoinPath(options.baseURL, fn.raw)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}
		m[u] = fn
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(slices.Collect(maps.Keys(m)), options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		fn, ok := m[resp.Request.URL.String()]
		if !ok {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("unexpected response url: %s", resp.Request.URL.String())
		}

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
			if err := util.Write(filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
		}

		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}
		for _, test := range root.Tests.UnameTest {
			if err := util.Write(filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "tests", "uname_test", fmt.Sprintf("%s.json", test.ID)))
			}
		}

		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
		}
		if root.Objects.UnameObject.ID != "" {
			if err := util.Write(filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)), root.Objects.UnameObject); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "objects", "uname_object", fmt.Sprintf("%s.json", root.Objects.UnameObject.ID)))
			}
		}

		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
		}
		for _, state := range root.States.UnameState {
			if err := util.Write(filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "states", "uname_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fn.os, fn.version, fn.ovalType(), "states", "uname_state", fmt.Sprintf("%s.json", state.ID)))
			}
		}

		return nil
	}); err != nil {
		return errors.Wrap(err, "pipeline get")
	}

	return nil
}

type variant string

const (
	variantNone     variant = ""
	variantAffected variant = "affected"
	variantPatch    variant = "patch"
)

type ovalfile struct {
	raw     string
	os      string
	version string
	variant variant
}

func (f ovalfile) ovalType() string {
	if f.variant == variantPatch {
		return "patch"
	}
	return "vulnerability"
}

func (opts options) walkIndexOf() ([]ovalfile, error) {
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

	m := make(map[string][]ovalfile)
	for _, selection := range d.Find("a").EachIter() {
		href, ok := selection.Attr("href")
		if !ok {
			continue
		}

		if f := func() *ovalfile {
			stem, ok := strings.CutSuffix(href, ".xml.gz")
			if !ok {
				return nil
			}

			variant := variantNone
			switch {
			case strings.HasSuffix(stem, "-affected"):
				variant = variantAffected
				stem = strings.TrimSuffix(stem, "-affected")
			case strings.HasSuffix(stem, "-patch"):
				variant = variantPatch
				stem = strings.TrimSuffix(stem, "-patch")
			}

			switch {
			case strings.HasPrefix(stem, "suse.linux.enterprise.desktop"):
				switch v := strings.TrimPrefix(stem, "suse.linux.enterprise.desktop."); v {
				case "10":
					return &ovalfile{
						raw:     href,
						os:      "suse.linux.enterprise.desktop",
						version: v,
						variant: variant,
					}
				default:
					// 11 and later, use suse.linux.enterprise.<version>
					return nil
				}
			case strings.HasPrefix(stem, "suse.linux.enterprise.server"):
				switch v := strings.TrimPrefix(stem, "suse.linux.enterprise.server."); v {
				case "9", "10":
					return &ovalfile{
						raw:     href,
						os:      "suse.linux.enterprise.server",
						version: v,
						variant: variant,
					}
				default:
					// 11 and later, use suse.linux.enterprise.<version>
					return nil
				}
			case strings.HasPrefix(stem, "suse.linux.enterprise.micro"):
				switch v := strings.TrimPrefix(stem, "suse.linux.enterprise.micro."); v {
				case "5": // ignore minor version OVALs, as minor versions are aggregated within major version OVAL
					return &ovalfile{
						raw:     href,
						os:      "suse.linux.enterprise.micro",
						version: v,
						variant: variant,
					}
				default:
					// 6 and later use suse.linux.micro.<version>
					return nil
				}
			case strings.HasPrefix(stem, "suse.linux.micro"):
				v := strings.TrimPrefix(stem, "suse.linux.micro.")

				// ignore minor version OVALs, as minor versions are aggregated within major version OVAL
				if strings.Contains(v, ".") {
					return nil
				}
				return &ovalfile{
					raw:     href,
					os:      "suse.linux.micro",
					version: v,
					variant: variant,
				}
			case strings.HasPrefix(stem, "suse.linux.enterprise"):
				v := strings.TrimPrefix(stem, "suse.linux.enterprise.")

				// ignore minor version OVALs, as minor versions are aggregated within major version OVAL
				if strings.Contains(v, "-sp") || strings.Contains(v, ".") {
					return nil
				}
				return &ovalfile{
					raw:     href,
					os:      "suse.linux.enterprise",
					version: v,
					variant: variant,
				}
			case strings.HasPrefix(stem, "opensuse.leap.micro"):
				return &ovalfile{
					raw:     href,
					os:      "opensuse.leap.micro",
					version: strings.TrimPrefix(stem, "opensuse.leap.micro."),
					variant: variant,
				}
			case strings.HasPrefix(stem, "opensuse.leap"):
				return &ovalfile{
					raw:     href,
					os:      "opensuse.leap",
					version: strings.TrimPrefix(stem, "opensuse.leap."),
					variant: variant,
				}
			case strings.HasPrefix(stem, "opensuse.tumbleweed"):
				return &ovalfile{
					raw:     href,
					os:      "opensuse.tumbleweed",
					version: "",
					variant: variant,
				}
			case strings.HasPrefix(stem, "opensuse"):
				return &ovalfile{
					raw:     href,
					os:      "opensuse",
					version: strings.TrimPrefix(stem, "opensuse."),
					variant: variant,
				}
			default:
				return nil
			}
		}(); f != nil {
			m[fmt.Sprintf("%s:%s", f.os, f.version)] = append(m[fmt.Sprintf("%s:%s", f.os, f.version)], *f)
		}
	}

	fns := make([]ovalfile, 0, len(m)*2)
	for e, os := range m {
		var vo *ovalfile
		for _, o := range os {
			switch o.variant {
			case variantNone:
				if vo == nil {
					vo = &o
				}
			case variantAffected:
				vo = &o
			case variantPatch:
				fns = append(fns, o)
			default:
				return nil, errors.Errorf("unexpected variant. expected: %q, actual: %q", []variant{variantNone, variantAffected, variantPatch}, o.variant)
			}
		}
		if vo == nil {
			// sanity check, but opensuse.leap:13.2 has -patch variant only
			switch e {
			case "opensuse.leap:13.2":
			default:
				return nil, errors.Errorf("no vulnerability oval found for %s", e)
			}
		}
		fns = append(fns, *vo)
	}
	return fns, nil
}
