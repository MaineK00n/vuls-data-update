package capec

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "mitre", "capec"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch MITRE Common Attack Pattern Enumerations and Classifications: CAPEC")
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch capec data")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var capec capec
	if err := json.NewDecoder(resp.Body).Decode(&capec); err != nil {
		return errors.Wrap(err, "decode json")
	}

	bar := progressbar.Default(int64(len(capec.Objects)))
	for _, o := range capec.Objects {
		if err := util.Write(filepath.Join(options.dir, o.Type, fmt.Sprintf("%s.json", o.ID)), o); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, o.Type, fmt.Sprintf("%s.json", o.ID)))
		}
		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}
