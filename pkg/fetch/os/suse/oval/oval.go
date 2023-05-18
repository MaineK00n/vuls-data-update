package oval

import (
	"bytes"
	"compress/gzip"
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

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const baseURL = "https://ftp.suse.com/pub/projects/security/oval/"

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
		dir:     filepath.Join(util.SourceDir(), "suse", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch SUSE OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, ovalname := range ovals {
		var osname, version string
		if strings.HasPrefix(ovalname, "suse.linux.enterprise.desktop") {
			osname = "suse.linux.enterprise.desktop"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "suse.linux.enterprise.desktop.")
		} else if strings.HasPrefix(ovalname, "suse.linux.enterprise.server") {
			osname = "suse.linux.enterprise.server"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "suse.linux.enterprise.server.")
		} else if strings.HasPrefix(ovalname, "opensuse.tumbleweed") {
			osname = "opensuse"
			version = "tumbleweed"
		} else if strings.HasPrefix(ovalname, "opensuse.leap") {
			osname = "opensuse.leap"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "opensuse.leap.")
		} else if strings.HasPrefix(ovalname, "opensuse") {
			osname = "opensuse"
			version = strings.TrimPrefix(strings.TrimSuffix(ovalname, ".xml.gz"), "opensuse.")
		} else {
			return errors.Wrapf(err, `unexpected ovalname. accepts: "<osname>.<version>.xml.gz", received: "%s"`, ovalname)
		}

		log.Printf("[INFO] Fetch %s", fmt.Sprintf("%s %s", osname, version))
		u, err := url.JoinPath(options.baseURL, ovalname)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}

		bs, err := util.FetchURL(u, options.retry)
		if err != nil {
			return errors.Wrap(err, "fetch oval")
		}

		r, err := gzip.NewReader(bytes.NewReader(bs))
		if err != nil {
			return errors.Wrap(err, "open oval as gzip")
		}

		var root root
		if err := xml.NewDecoder(r).Decode(&root); err != nil {
			return errors.Wrap(err, "decode oval")
		}

		dir := filepath.Join(options.dir, osname, version)
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
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "tests", "tests.json.gz"))
		}
		bar.Increment()

		if err := util.Write(filepath.Join(dir, "objects", "objects.json.gz"), root.Objects); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "objects", "objects.json.gz"))
		}
		bar.Increment()

		if err := util.Write(filepath.Join(dir, "states", "states.json.gz"), root.States); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "states", "states.json.gz"))
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
		if !strings.HasSuffix(txt, ".xml.gz") {
			return
		}
		if !(strings.HasPrefix(txt, "opensuse") ||
			strings.HasPrefix(txt, "opensuse.leap") ||
			strings.HasPrefix(txt, "opensuse.tumbleweed") ||
			strings.HasPrefix(txt, "suse.linux.enterprise.desktop") ||
			strings.HasPrefix(txt, "suse.linux.enterprise.server")) || strings.HasPrefix(txt, "opensuse.leap.micro") {
			return
		}
		if strings.Contains(txt, "-patch") || strings.Contains(txt, "-affected") {
			return
		}
		ovals = append(ovals, txt)
	})
	return ovals, nil
}
