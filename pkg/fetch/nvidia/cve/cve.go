package cve

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://github.com/NVIDIA/product-security/archive/refs/heads/main.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "nvidia", "cve"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch NVIDIA CVE Record")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch nvidia cve record")
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

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// CVE Records are laid out as <root>/<initial publication year>/<bulletin id>/CVE-yyyy-\d{4,}.json.
		// The record itself carries neither a date nor the bulletin it belongs to, and the same CVE ID may appear
		// under several bulletins with differing content, so the bulletin directory is preserved as the output path.
		ss := strings.Split(hdr.Name, "/")
		if len(ss) != 4 || !strings.HasPrefix(ss[3], "CVE-") || filepath.Ext(ss[3]) != ".json" {
			continue
		}

		var record CVE
		if err := json.UnmarshalRead(tr, &record); err != nil {
			return errors.Wrapf(err, "decode %s", hdr.Name)
		}

		if err := util.Write(filepath.Join(options.dir, ss[1], ss[2], fmt.Sprintf("%s.json", record.CVEMetadata.CVEID)), record); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, ss[1], ss[2], fmt.Sprintf("%s.json", record.CVEMetadata.CVEID)))
		}
	}

	return nil
}
