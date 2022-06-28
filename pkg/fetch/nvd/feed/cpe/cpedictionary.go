package cpe

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const cpeDictionaryURL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

type options struct {
	url   string
	dir   string
	retry int
}

type Option interface {
	apply(*options)
}

type urlOption string

func (u urlOption) apply(opts *options) {
	opts.url = string(u)
}

func WithURL(url string) Option {
	return urlOption(url)
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
		url:   cpeDictionaryURL,
		dir:   filepath.Join(util.SourceDir(), "nvd", "feed", "cpe"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	cpeDict, err := options.fetchCPEDictinoary()
	if err != nil {
		return errors.Wrap(err, "fetch cpe dictionary")
	}

	if err := util.Write(filepath.Join(options.dir, "cpe-dictionary.json"), cpeDict); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "cpe-dictionary.json"))
	}

	return nil
}

func (opts options) fetchCPEDictinoary() ([]CPEDictItem, error) {
	var cpes []CPEDictItem

	log.Printf(`[INFO] Fetch NVD CPE Dictinoary`)
	bs, err := util.FetchURL(opts.url, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch cpe dictionary feed")
	}

	r, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "open cpe dictionary as gzip")
	}
	defer r.Close()

	parseDateFn := func(layout string, v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse(layout, v); err == nil {
			t = t.UTC()
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

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
				DeprecationDate: parseDateFn("2006-01-02T15:04:05.000Z", item.DeprecationDate),
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
					Date: parseDateFn("2006-01-02T15:04:05.000-07:00", item.Cpe23Item.Deprecation.Date),
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
