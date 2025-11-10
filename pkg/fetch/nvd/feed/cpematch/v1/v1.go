package v1

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"

type options struct {
	baseURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type baseURLOption string

func (u baseURLOption) apply(opts *options) {
	opts.baseURL = string(u)
}

func WithBaseURL(url string) Option {
	return baseURLOption(url)
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
		baseURL: baseURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cpematch", "v1"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf(`[INFO] Fetch NVD CPE Match Feed 1.0`)
	cpeMatch, err := options.fetch()
	if err != nil {
		return errors.Wrap(err, "fetch cpe match feed 1.0")
	}

	dv := hash32([]byte("vendor:product"))

	bar := progressbar.Default(int64(len(cpeMatch)))
	for cpe, items := range cpeMatch {
		d := dv

		wfn, err := naming.UnbindFS(cpe)
		if err == nil {
			d = hash32([]byte(fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))))
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%x.json", hash64([]byte(cpe)))), items); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%x.json", hash64([]byte(cpe)))))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}

func (opts options) fetch() (map[string][]CpeMatchItem, error) {
	cpes := make(map[string][]CpeMatchItem)

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cpe match")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "open cpe match as gzip")
	}
	defer r.Close()

	d := json.NewDecoder(r)
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: {"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "string: matches"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: ["`)
	}
	for d.More() {
		var e CpeMatchItem
		if err := d.Decode(&e); err != nil {
			return nil, errors.Wrap(err, "decode element")
		}
		cpes[e.Cpe23URI] = append(cpes[e.Cpe23URI], e)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: ]"`)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.Wrap(err, `return next JSON token. expected: "json.Delim: }"`)
	}

	return cpes, nil
}

func hash32(message []byte) uint32 {
	h := fnv.New32()
	h.Write(message)
	return h.Sum32()
}

func hash64(message []byte) uint64 {
	h := fnv.New64()
	h.Write(message)
	return h.Sum64()
}
