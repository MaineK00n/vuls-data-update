package vex

import (
	"archive/tar"
	"encoding/json/v2"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "ubuntu", "vex"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Ubuntu OpenVEX")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch vex data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	r, err := xz.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create xz reader")
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "next tar reader")
		}

		if hdr.FileInfo().IsDir() || filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var vex VEX
		if err := json.UnmarshalRead(tr, &vex); err != nil {
			return errors.Wrap(err, "decode json")
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json", strings.TrimPrefix(vex.Metadata.ID, "https://github.com/canonical/ubuntu-security-notices/blob/main/vex/"))), vex); err != nil {
			return errors.Wrapf(err, "write %s", fmt.Sprintf("%s.json", strings.TrimPrefix(vex.Metadata.ID, "https://github.com/canonical/ubuntu-security-notices/blob/main/vex/")))
		}
	}

	return nil
}
