package ovalv1

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type options struct {
	indexOf string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type indexOfOption string

func (i indexOfOption) apply(opts *options) {
	opts.indexOf = string(i)
}

func WithIndexOf(u string) Option {
	return indexOfOption(u)
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
		indexOf: "https://www.redhat.com/security/data/oval/",
		dir:     filepath.Join(util.SourceDir(), "redhat", "ovalv1"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch RedHat OVAL")
	urls, err := options.walkIndexOf(options.indexOf)
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, u := range urls {
		v := strings.TrimSuffix(strings.TrimPrefix(path.Base(u), "com.redhat.rhsa-RHEL"), ".xml.bz2")
		log.Printf(`[INFO] Fetch %s`, v)

		bs, err := util.FetchURL(u, options.retry)
		if err != nil {
			return errors.Wrap(err, "fetch oval")
		}

		var root root
		if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
			return errors.Wrap(err, "decode oval")
		}

		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", dir)
		}

		bar := pb.StartNew(len(root.Definitions.Definition) + 4)
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

		if err := util.Write(filepath.Join(dir, "variables", "variables.json.gz"), root.Variables); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "variables", "variables.json.gz"))
		}
		bar.Increment()

		bar.Finish()
	}

	return nil
}

func (opts options) walkIndexOf(indexOfURL string) ([]string, error) {
	bs, err := util.FetchURL(indexOfURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var files []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "com.redhat.rhsa-RHEL") {
			return
		}
		files = append(files, txt)
	})

	urls := make([]string, 0, len(files))
	for _, f := range files {
		u, err := url.JoinPath(indexOfURL, f)
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}
		urls = append(urls, u)
	}
	return urls, nil
}
