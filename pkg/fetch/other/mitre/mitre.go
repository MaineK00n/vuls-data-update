package mitre

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/net/html/charset"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const dataURL = "https://cve.mitre.org/data/downloads/allitems-cvrf.xml"

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
		dir:     filepath.Join(util.SourceDir(), "mitre"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Printf("[INFO] Fetch MITRE CVE List")
	bs, err := util.FetchURL(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch mitre data")
	}

	var doc cvrfdoc
	d := xml.NewDecoder(bytes.NewReader(bs))
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&doc); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	parseDateFn := func(v string) *time.Time {
		if v == "" {
			return nil
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	vs := make([]Vulnerability, 0, len(doc.Vulnerability))
	for _, dv := range doc.Vulnerability {
		v := Vulnerability{
			Title:      dv.Title,
			CVE:        dv.CVE,
			References: dv.References,
		}

		for _, n := range dv.Notes {
			switch n.Type {
			case "Description":
				v.Notes.Description = n.Text
			case "Other":
				switch n.Title {
				case "Published":
					v.Notes.Published = parseDateFn(n.Text)
				case "Modified":
					v.Notes.Modified = parseDateFn(n.Text)
				default:
					log.Printf(`[WARN] unsupport Note Title. accepts: ["Published", "Modified"], received: "%s"`, n.Title)
				}
			default:
				log.Printf(`[WARN] unsupport Note type. accepts: ["Description", "Other"], received: "%s"`, n.Type)
			}
		}

		vs = append(vs, v)
	}

	if err := os.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}
	bar := pb.StartNew(len(vs))
	for _, v := range vs {
		if err := func() error {
			y := strings.Split(v.CVE, "-")[1]

			if err := os.MkdirAll(filepath.Join(options.dir, y), os.ModePerm); err != nil {
				return errors.Wrapf(err, "mkdir %s", filepath.Join(options.dir, y))
			}

			f, err := os.Create(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CVE)))
			if err != nil {
				return errors.Wrapf(err, "create %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CVE)))
			}
			defer f.Close()

			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(v); err != nil {
				return errors.Wrap(err, "encode data")
			}
			return nil
		}(); err != nil {
			return err
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
