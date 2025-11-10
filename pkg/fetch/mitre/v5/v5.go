package v5

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "v5"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch MITRE CVE V5 List")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch mitre data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var vs []CVE

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

		if hdr.FileInfo().IsDir() {
			continue
		}

		if !strings.HasPrefix(filepath.Base(hdr.Name), "CVE-") || filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var c CVE
		if err := json.NewDecoder(tr).Decode(&c); err != nil {
			return errors.Wrap(err, "decode json")
		}

		vs = append(vs, c)
	}

	bar := progressbar.Default(int64(len(vs)))
	for _, v := range vs {
		splitted, err := util.Split(v.CVEMetadata.CVEID, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVEMetadata.CVEID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.CVEMetadata.CVEID)
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.CVEMetadata.CVEID)))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
