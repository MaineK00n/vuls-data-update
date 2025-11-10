package product

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

const dataURL = "https://api.msrc.microsoft.com/sug/v2.0/sugodata/v2.0/en-US/affectedProduct?$skip=0"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "microsoft", "product"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Microsoft Product")

	bar := progressbar.Default(-1)
	u := options.dataURL
	for u != "" {
		r, err := func() (*response, error) {
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch product")
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var r response
			if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
				return nil, errors.Wrap(err, "decode json")
			}

			return &r, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		for _, v := range r.Value {
			splitted, err := util.Split(v.ID, "-", "-", "-", "-")
			if err != nil {
				return errors.Errorf("unexpected ID format. expected: %q, actual: %q", "00000000-0000-0000-0000-000000000000", v.ID)
			}
			if err := util.Write(filepath.Join(options.dir, splitted[0], splitted[1], splitted[2], splitted[3], fmt.Sprintf("%s.json", v.ID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0], splitted[1], splitted[2], splitted[3], fmt.Sprintf("%s.json", v.ID)))
			}

			_ = bar.Add(1)
		}

		u = r.OdataNextLink
	}
	_ = bar.Close()

	return nil
}
