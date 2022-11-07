package alpine

import (
	"bytes"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const baseURL = "https://secdb.alpinelinux.org/"

type options struct {
	baseURL        string
	dir            string
	retry          int
	compressFormat string
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:        baseURL,
		dir:            filepath.Join(util.SourceDir(), "alpine"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	releases, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for _, r := range releases {
		log.Printf("[INFO] Fetch Alpine Linux %s", r)
		files, err := options.walkDistroVersion(r)
		if err != nil {
			return errors.Wrapf(err, "walk alpine linux %s", r)
		}

		advs, err := options.fetchAdvisory(r, files)
		if err != nil {
			return errors.Wrapf(err, "fetch alpine linux %s advisory %q", r, files)
		}

		dir := filepath.Join(options.dir, strings.TrimPrefix(r, "v"))
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "mkdir %s", dir)
		}
		for filename, adv := range advs {
			bs, err := json.Marshal(adv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(dir, filename), options.compressFormat), bs, options.compressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(dir, filename))
			}
		}
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

	var releases []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasPrefix(txt, "v") {
			return
		}
		releases = append(releases, strings.TrimSuffix(txt, "/"))
	})
	return releases, nil
}

func (opts options) walkDistroVersion(release string) ([]string, error) {
	u, err := url.JoinPath(opts.baseURL, release)
	if err != nil {
		return nil, errors.Wrap(err, "join url path")
	}

	bs, err := util.FetchURL(u, opts.retry)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch alpine linux %s index of", release)
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var files []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := selection.Text()
		if !strings.HasSuffix(txt, ".json") {
			return
		}
		files = append(files, txt)
	})
	return files, nil
}

func (opts options) fetchAdvisory(release string, files []string) (map[string]Advisory, error) {
	advs := make(map[string]Advisory, 2)
	for _, f := range files {
		u, err := url.JoinPath(opts.baseURL, release, f)
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}

		bs, err := util.FetchURL(u, opts.retry)
		if err != nil {
			return nil, errors.Wrapf(err, "fetch alpine linux %s %s", release, f)
		}

		var secdb secdb
		if err := json.Unmarshal(bs, &secdb); err != nil {
			return nil, errors.Wrapf(err, "unmarshal alpine linux %s %s", release, f)
		}
		pkgs := make([]Package, 0, len(secdb.Packages))
		for _, p := range secdb.Packages {
			pkgs = append(pkgs, p.Pkg)
		}
		advs[f] = Advisory{
			Apkurl:        secdb.Apkurl,
			Archs:         secdb.Archs,
			Reponame:      secdb.Reponame,
			Urlprefix:     secdb.Urlprefix,
			Distroversion: secdb.Distroversion,
			Packages:      pkgs,
		}
	}
	return advs, nil
}
