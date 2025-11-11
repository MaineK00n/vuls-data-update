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
	for _, oval := range ovals {
		u, err := url.JoinPath(options.baseURL, oval)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}
		us = append(us, u)
	}

	if err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).PipelineGet(us, options.concurrency, options.wait, false, func(resp *http.Response) error {
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		ovaltype, osname, version, err := func() (string, string, string, error) {
			lhs, rhs, _ := strings.Cut(strings.TrimSuffix(path.Base(resp.Request.URL.Path), ".xml.gz"), "-")
			var ovaltype string
			switch rhs {
			case "affected", "":
				ovaltype = "vulnerability"
			case "patch":
				ovaltype = "patch"
			default:
				return "", "", "", errors.Errorf("unexpected ovaltype. accepts: %q, received: %q", "<osname>.<version>(-<type>).xml.gz", path.Base(resp.Request.URL.Path))
			}

			switch {
			case strings.HasPrefix(lhs, "suse.linux.enterprise.desktop"):
				return ovaltype, "suse.linux.enterprise.desktop", strings.TrimPrefix(lhs, "suse.linux.enterprise.desktop."), nil
			case strings.HasPrefix(lhs, "suse.linux.enterprise.server"):
				return ovaltype, "suse.linux.enterprise.server", strings.TrimPrefix(lhs, "suse.linux.enterprise.server."), nil
			case strings.HasPrefix(lhs, "suse.linux.enterprise.micro"):
				return ovaltype, "suse.linux.enterprise.micro", strings.TrimPrefix(lhs, "suse.linux.enterprise.micro."), nil
			case strings.HasPrefix(lhs, "opensuse.leap.micro"):
				return ovaltype, "opensuse.leap.micro", strings.TrimPrefix(lhs, "opensuse.leap.micro."), nil
			case strings.HasPrefix(lhs, "opensuse.leap"):
				return ovaltype, "opensuse.leap", strings.TrimPrefix(lhs, "opensuse.leap."), nil
			case strings.HasPrefix(lhs, "opensuse"):
				return ovaltype, "opensuse", strings.TrimPrefix(lhs, "opensuse."), nil
			default:
				return "", "", "", errors.Errorf("unexpected ovalname. accepts: %q, received: %q", "<osname>.<version>", lhs)
			}
		}()
		if err != nil {
			return errors.Wrap(err, "parse oval name")
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

	ovals := make(map[string]string)
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasSuffix(txt, ".xml.gz") {
			return
		}

		switch {
		case strings.HasPrefix(txt, "opensuse"), strings.HasPrefix(txt, "opensuse.leap"), strings.HasPrefix(txt, "opensuse.leap.micro"), strings.HasPrefix(txt, "opensuse.tumbleweed"),
			strings.HasPrefix(txt, "suse.linux.enterprise.desktop"), strings.HasPrefix(txt, "suse.linux.enterprise.server"):
		case strings.HasPrefix(txt, "suse.linux.enterprise.micro"):
			switch txt {
			case "suse.linux.enterprise.micro.5-affected.xml.gz", "suse.linux.enterprise.micro.5-patch.xml.gz", "suse.linux.enterprise.micro.5.xml.gz":
				// SLEM 5 series has "5" and "5.y". SLEM 6 series has "6.y" only. Exclude "5" here.
				return
			default:
			}
		default:
			return
		}

		switch {
		case strings.Contains(txt, "-affected"):
			ovals[strings.TrimSuffix(txt, "-affected.xml.gz")] = txt
		case strings.Contains(txt, "-patch"):
			ovals[strings.TrimSuffix(txt, ".xml.gz")] = txt
		default:
			if _, ok := ovals[strings.TrimSuffix(txt, ".xml.gz")]; !ok {
				ovals[strings.TrimSuffix(txt, ".xml.gz")] = txt
			}
		}
	})
	return slices.Collect(maps.Values(ovals)), nil
}
