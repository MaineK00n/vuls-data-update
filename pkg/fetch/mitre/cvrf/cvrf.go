package cvrf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/net/html/charset"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
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
		dir:     filepath.Join(util.CacheDir(), "mitre", "cvrf"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch MITRE CVE CVRF List")
	bs, err := utilhttp.Get(options.dataURL, options.retry)
	if err != nil {
		return errors.Wrap(err, "fetch mitre data")
	}

	var doc cvrfdoc
	d := xml.NewDecoder(bytes.NewReader(bs))
	d.CharsetReader = charset.NewReaderLabel
	if err := d.Decode(&doc); err != nil {
		return errors.Wrap(err, "decode xml")
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
					v.Notes.Published = n.Text
				case "Modified":
					v.Notes.Modified = n.Text
				default:
					log.Printf(`[WARN] unsupport Note Title. accepts: ["Published", "Modified"], received: "%s"`, n.Title)
				}
			default:
				log.Printf(`[WARN] unsupport Note type. accepts: ["Description", "Other"], received: "%s"`, n.Type)
			}
		}

		vs = append(vs, v)
	}

	bar := pb.StartNew(len(vs))
	for _, v := range vs {
		y := strings.Split(v.CVE, "-")[1]
		if _, err := strconv.Atoi(y); err != nil {
			continue
		}

		if err := util.Write(filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CVE)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, y, fmt.Sprintf("%s.json", v.CVE)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
