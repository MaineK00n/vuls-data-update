package ovalv2

import (
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
)

const (
	feedURL            = "https://www.redhat.com/security/data/oval/v2/feed.json"
	repositoryToCPEURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"
)

type options struct {
	feedURL            string
	repositoryToCPEURL string
	dir                string
	retry              int
}

type Option interface {
	apply(*options)
}

type feedURLOption string

func (u feedURLOption) apply(opts *options) {
	opts.feedURL = string(u)
}

func WithFeedURL(u string) Option {
	return feedURLOption(u)
}

type repositoryToCPEURLOption string

func (u repositoryToCPEURLOption) apply(opts *options) {
	opts.repositoryToCPEURL = string(u)
}

func WithRepositoryToCPEURL(u string) Option {
	return repositoryToCPEURLOption(u)
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
		feedURL:            feedURL,
		repositoryToCPEURL: repositoryToCPEURL,
		dir:                filepath.Join(util.SourceDir(), "redhat", "ovalv2"),
		retry:              3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch RedHat OVAL")
	log.Println("[INFO] Fetch Redhat Repository to CPE")
	bs, err := util.FetchURL(options.repositoryToCPEURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch repository to cpe")
	}

	var repo2cpe RepositoryToCPE
	if err := json.Unmarshal(bs, &repo2cpe); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	if err := util.Write(filepath.Join(options.dir, "repository-to-cpe.json.gz"), repo2cpe); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "repository-to-cpe.json.gz"))
	}

	bs, err = util.FetchURL(options.feedURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch feed")
	}

	var f feed
	if err := json.Unmarshal(bs, &f); err != nil {
		return errors.Wrap(err, "unmarshal json")
	}

	var urls []string
	for _, e := range f.Feed.Entry {
		urls = append(urls, e.Content.Src)
	}

	for _, u := range urls {
		d, file := path.Split(u)
		name := strings.TrimSuffix(file, ".oval.xml.bz2")
		v := strings.TrimPrefix(path.Base(path.Clean(d)), "RHEL")

		log.Printf("[INFO] Fetch RedHat %s %s OVAL", v, name)
		bs, err := util.FetchURL(u, options.retry)
		if err != nil {
			return errors.Wrap(err, "fetch advisory")
		}

		var root root
		if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
			return errors.Wrap(err, "unmarshal advisory")
		}

		dir := filepath.Join(options.dir, v, name)
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
