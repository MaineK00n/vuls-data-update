package oval

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian/codename"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
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
		dir:     filepath.Join(util.SourceDir(), "debian", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Debian OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		code := strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml"), "oval-definitions-")
		v, ok := codename.CodeToVer[code]
		if !ok {
			return errors.Errorf("unexpected codename. accepts %q, received %q", maps.Keys(codename.CodeToVer), code)
		}

		log.Printf("[INFO] Fetch Debian %s OVAL", v)
		root, err := options.fetch(ovalname)
		if err != nil {
			return errors.Wrapf(err, "fetch debian %s oval", v)
		}

		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", dir)
		}

		bar := pb.StartNew(len(root.Definitions.Definition) + 3)
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(dir, "definitions", fmt.Sprintf("%s.json.gz", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(dir, "definitions", fmt.Sprintf("%s.json.gz", def.ID)))
			}
			bar.Increment()
		}

		if err := util.Write(filepath.Join(dir, "tests", "tests.json.gz"), root.Tests); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(dir, "tests", "tests.json.gz"))
		}
		bar.Increment()

		if err := util.Write(filepath.Join(dir, "objects", "objects.json.gz"), root.Objects); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(dir, "objects", "objects.json.gz"))
		}
		bar.Increment()

		if err := util.Write(filepath.Join(dir, "states", "states.json.gz"), root.States); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(dir, "states", "states.json.gz"))
		}
		bar.Increment()

		bar.Finish()
	}
	return nil
}

func (opts options) walkIndexOf() ([]string, error) {
	bs, err := util.FetchURL(opts.baseURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
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

	bs, err := util.FetchURL(u, opts.retry)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}

	var r root
	if err := xml.Unmarshal(bs, &r); err != nil {
		return nil, errors.Wrap(err, "unmarshal xml")
	}

	return &r, nil
}
