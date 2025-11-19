package v2

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json/v2"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cpematch", "v2"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf(`[INFO] Fetch NVD CPE Match Feed 2.0`)
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.baseURL)
	if err != nil {
		return errors.Wrap(err, "fetch cpe match feed 2.0")
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

		if hdr.FileInfo().IsDir() {
			continue
		}

		if filepath.Ext(hdr.Name) != ".json" {
			continue
		}

		var feed api20
		if err := json.UnmarshalRead(tr, &feed); err != nil {
			return errors.Wrap(err, "decode json")
		}

		dv := hash32([]byte("vendor:product"))

		for _, m := range feed.MatchData {
			d := dv

			wfn, err := naming.UnbindFS(m.MatchCriteria.Criteria)
			if err == nil {
				d = hash32([]byte(fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))))
			}

			if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%s.json", m.MatchCriteria.MatchCriteriaID)), m.MatchCriteria); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%s.json", m.MatchCriteria.MatchCriteriaID)))
			}
		}
	}

	return nil
}

func hash32(message []byte) uint32 {
	h := fnv.New32()
	h.Write(message)
	return h.Sum32()
}
