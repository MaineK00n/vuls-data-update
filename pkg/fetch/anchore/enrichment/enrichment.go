package enrichment

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json/v2"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/anchore/cve-data-enrichment/archive/refs/heads/main.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "anchore", "enrichment"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Anchore Enrichment")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() || !strings.HasPrefix(hdr.Name, "cve-data-enrichment-main/data/anchore/") || filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		ss := strings.Split(hdr.Name, string(os.PathSeparator))
		if len(ss) != 5 {
			return errors.Errorf("unexpected filepath. expected: %q, actual: %q", "cve-data-enrichment-main/data/anchore/yyyy/CVE-yyyy-\\d{4,}.json", hdr.Name)
		}

		var e Enrichment
		if err := json.UnmarshalRead(tr, &e); err != nil {
			return errors.Wrapf(err, "unmarshal %s", hdr.Name)
		}

		if err := util.Write(filepath.Join(options.dir, ss[3], ss[4]), e); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ss[3], ss[4]))
		}
	}

	return nil
}
