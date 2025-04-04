package oval

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://packages.vmware.com/photon/photon_oval_definitions/"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "photon", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Photon OVAL")

	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		ver := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "com.vmware.phsa-photon")

		log.Printf("[INFO] Fetch Photon %s OVAL", ver)
		root, err := options.fetch(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch alma %s oval", ver)
		}

		log.Printf("[INFO] Fetch Photon %s Definitions", ver)
		bar := pb.StartNew(len(root.Definitions.Definition))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Photon %s Tests", ver)
		bar = pb.StartNew(len(root.Tests.RpminfoTest))
		for _, test := range root.Tests.RpminfoTest {
			if err := util.Write(filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "tests", "rpminfo_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Photon %s Objects", ver)
		bar = pb.StartNew(len(root.Objects.RpminfoObject))
		for _, object := range root.Objects.RpminfoObject {
			if err := util.Write(filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "objects", "rpminfo_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Photon %s States", ver)
		bar = pb.StartNew(len(root.States.RpminfoState))
		for _, state := range root.States.RpminfoState {
			if err := util.Write(filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ver, "states", "rpminfo_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()
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

	var ovals []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasSuffix(txt, ".xml.gz") {
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
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close() //nolint:errcheck

	var r root
	if err := xml.NewDecoder(gr).Decode(&r); err != nil {
		return nil, errors.Wrap(err, "decode xml")
	}

	return &r, nil
}
