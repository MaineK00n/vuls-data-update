package v1

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const cpeDictionaryURL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

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
		baseURL: cpeDictionaryURL,
		dir:     filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cpe", "v1"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf(`[INFO] Fetch NVD CPE Dictionary`)
	cpeDict, err := options.fetch()
	if err != nil {
		return errors.Wrap(err, "fetch cpe dictionary")
	}

	dv := hash32([]byte("vendor:product"))

	bar := progressbar.Default(int64(len(cpeDict)))
	for _, cpe := range cpeDict {
		d := dv

		wfn, err := naming.UnbindURI(cpe.Name)
		if err == nil {
			d = hash32([]byte(fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))))
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%x.json", hash64([]byte(cpe.Name)))), cpe); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%x", d), fmt.Sprintf("%x.json", hash64([]byte(cpe.Name)))))
		}

		_ = bar.Add(1)
	}
	_ = bar.Close()

	return nil
}

func (opts options) fetch() ([]CPEDictItem, error) {
	var cpes []CPEDictItem

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cpe dictionary feed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "open cpe dictionary as gzip")
	}
	defer r.Close()

	d := xml.NewDecoder(r)
	for {
		t, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.Wrap(err, "return next XML token")
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local != "cpe-item" {
				break
			}
			var item cpeDictItem
			if err := d.DecodeElement(&item, &se); err != nil {
				return nil, errors.Wrap(err, "decode element")
			}

			c := CPEDictItem{
				Name:            item.Name,
				DeprecationDate: item.DeprecationDate,
				Title:           item.Title,
				References:      item.References,
				Cpe23Item: CPEDictCpe23Item{
					Name: item.Cpe23Item.Name,
				},
			}

			if item.Deprecated != "" {
				b, err := strconv.ParseBool(item.Deprecated)
				if err != nil {
					log.Printf(`[WARN] unexpected Deprecated Value in %s. accepts: ["true", "false"], received: "%s"`, item.Cpe23Item.Name, item.Deprecated)
				} else {
					c.Deprecated = b
				}
			}
			if item.Cpe23Item.Deprecation != nil {
				c.Cpe23Item.Deprecation = &CPEDictDeprecation{
					Date: item.Cpe23Item.Deprecation.Date,
					DeprecatedBy: CPEDictDeprectedBy{
						Name: item.Cpe23Item.Deprecation.DeprecatedBy.Name,
						Type: item.Cpe23Item.Deprecation.DeprecatedBy.Type,
					},
				}
			}
			cpes = append(cpes, c)
		default:
		}
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
