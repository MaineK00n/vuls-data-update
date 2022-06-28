package v4

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
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
		dir:     filepath.Join(util.CacheDir(), "mitre", "v4"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch MITRE CVE V4 List")
	bs, err := utilhttp.Get(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch mitre data")
	}

	var root root

	gr, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	d := xml.NewDecoder(gr)
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&root); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	bar := pb.StartNew(len(root.Item))
	for _, v := range root.Item {
		y := strings.Split(v.Name, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			continue
		}

		if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.Name)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.Name)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
