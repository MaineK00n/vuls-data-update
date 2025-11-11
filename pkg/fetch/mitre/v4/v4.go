package v4

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/html/charset"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://cve.mitre.org/data/downloads/allitems.xml.gz"

type options struct {
	dataURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type dataURLOption string

func (u dataURLOption) apply(opts *options) {
	opts.dataURL = string(u)
}

func WithDataURL(url string) Option {
	return dataURLOption(url)
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
		dataURL: dataURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "v4"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch MITRE CVE V4 List")
	h := make(http.Header)
	h.Set("Accept-Encoding", "gzip")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL, utilhttp.WithRequestHeader(h))
	if err != nil {
		return errors.Wrap(err, "fetch mitre data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var root root

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	d := xml.NewDecoder(gr)
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&root); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	bar := progressbar.Default(int64(len(root.Item)))
	for _, v := range root.Item {
		splitted, err := util.Split(v.Name, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.Name)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.Name)
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.Name)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.Name)))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
