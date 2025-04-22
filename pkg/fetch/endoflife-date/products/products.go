package products

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/endoflife-date/endoflife.date/archive/refs/heads/master.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "endoflife-date", "products"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch endoflife.date products")

	re, err := regexp.Compile(`(?s)^---\n(.*?)\n---`)
	if err != nil {
		return errors.Wrap(err, "compile regexp")
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close() //nolint:errcheck

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() || filepath.Base(filepath.Dir(hdr.Name)) != "products" || filepath.Ext(hdr.Name) != ".md" {
			continue
		}

		bs, err := io.ReadAll(tr)
		if err != nil {
			return errors.Wrap(err, "read all")
		}

		ymlhdr := re.Find(bs)
		if ymlhdr == nil {
			return errors.Errorf("unexpected format. expected: %q, actual: %q", "---\n<yaml>\n---", string(bs))
		}

		var product Product
		if err := yaml.Unmarshal(ymlhdr, &product); err != nil {
			return errors.Wrap(err, "unmarshal yaml")
		}

		if err := util.Write(filepath.Join(options.dir, product.Category, fmt.Sprintf("%s.json", strings.TrimSuffix(filepath.Base(hdr.Name), ".md"))), product); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, product.Category, fmt.Sprintf("%s.json", strings.TrimSuffix(filepath.Base(hdr.Name), ".md"))))
		}
	}

	return nil
}
