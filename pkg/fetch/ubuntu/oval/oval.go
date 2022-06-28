package oval

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://security-metadata.canonical.com/oval/"

var services = []string{"esm", "esm-apps", "esm-infra", "fips", "fips-updates"}

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
		dir:     filepath.Join(util.CacheDir(), "ubuntu", "oval"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Ubuntu OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for name, href := range ovals {
		release, service, ok := strings.Cut(name, "/")
		if !ok {
			return errors.Errorf("unexpected oval name. expected: \"<release>/<service>\", actual: %q", name)
		}

		log.Printf("[INFO] Fetch Ubuntu %s/%s", release, service)
		u, err := url.JoinPath(options.baseURL, href)
		if err != nil {
			return errors.Wrap(err, "join url path")
		}

		bs, err := utilhttp.Get(u, options.retry)
		if err != nil {
			return errors.Wrap(err, "fetch oval")
		}

		var root root
		if err := xml.NewDecoder(bzip2.NewReader(bytes.NewReader(bs))).Decode(&root); err != nil {
			return errors.Wrap(err, "decode oval")
		}

		log.Printf("[INFO] Fetch Ubuntu %s/%s Definitions", release, service)
		bar := pb.StartNew(len(root.Definitions.Definition))
		for _, def := range root.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, release, service, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, service, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu %s/%s Tests", release, service)
		bar = pb.StartNew(len(root.Tests.Textfilecontent54Test))
		for _, test := range root.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, release, service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu %s/%s Objects", release, service)
		bar = pb.StartNew(len(root.Objects.Textfilecontent54Object))
		for _, object := range root.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, release, service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu %s/%s States", release, service)
		bar = pb.StartNew(len(root.States.Textfilecontent54State))
		for _, state := range root.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, release, service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu %s/%s Variables", release, service)
		bar = pb.StartNew(len(root.Variables.ConstantVariable))
		for _, variable := range root.Variables.ConstantVariable {
			if err := util.Write(filepath.Join(options.dir, release, service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)), variable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)))
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (opts options) walkIndexOf() (map[string]string, error) {
	bs, err := utilhttp.Get(opts.baseURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch index of")
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	ovals := map[string]string{}
	d.Find("table").Each(func(_ int, s *goquery.Selection) {
		s.Find("tr").Each(func(i int, r *goquery.Selection) {
			if i == 0 {
				return
			}
			if r.Find("th").First().Text() != "CVE" {
				return
			}
			var release string
			r.Find("td").EachWithBreak(func(itd int, d *goquery.Selection) bool {
				switch itd {
				case 0:
					lhs, rhs, _ := strings.Cut(d.Text(), "/")
					switch {
					case slices.Contains(services, lhs):
						release = fmt.Sprintf("%s/%s", rhs, lhs)
					case slices.Contains(services, rhs):
						release = fmt.Sprintf("%s/%s", lhs, rhs)
					default:
						if lhs == "" {
							ret, err := r.Html()
							if err != nil {
								ret = fmt.Sprintf("failed to get html. err: %s", err)
							}
							log.Printf("[WARN] not found release. row: %s", ret)
							return false
						}
						release = fmt.Sprintf("%s/main", lhs)
					}
				case 1:
					if release == "" {
						ret, err := r.Html()
						if err != nil {
							ret = fmt.Sprintf("failed to get html. err: %s", err)
						}
						log.Printf("[WARN] not set release. row: %s", ret)
						return false
					}

					f := d.Find("a").First().Text()
					if f == "" {
						ret, err := r.Html()
						if err != nil {
							ret = fmt.Sprintf("failed to get html. err: %s", err)
						}
						log.Printf("[WARN] not found file name. row: %s", ret)
						return false
					}

					if !strings.HasPrefix(f, "oci.") || !strings.HasSuffix(f, ".cve.oval.xml.bz2") {
						return false
					}

					ovals[release] = f
				default:
					return false
				}
				return true
			})
		})
	})
	return ovals, nil
}