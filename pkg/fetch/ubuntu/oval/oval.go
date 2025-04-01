package oval

import (
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
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

var services = []string{"esm", "esm-apps", "esm-infra", "fips", "fips-updates", "fips-preview", "bluefield", "realtime"}

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "ubuntu", "oval"),
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

	for name, href := range ovals.CVE {
		release, service, ok := strings.Cut(name, "/")
		if !ok {
			return errors.Errorf("unexpected oval name. expected: \"<release>/<service>\", actual: %q", name)
		}

		log.Printf("[INFO] Fetch Ubuntu CVE %s/%s", release, service)
		r, err := func() (*cveroot, error) {
			u, err := url.JoinPath(options.baseURL, href)
			if err != nil {
				return nil, errors.Wrap(err, "join url path")
			}

			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch oval")
			}
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var root cveroot
			if err := xml.NewDecoder(bzip2.NewReader(resp.Body)).Decode(&root); err != nil {
				return nil, errors.Wrap(err, "decode oval")
			}

			return &root, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		log.Printf("[INFO] Fetch Ubuntu CVE %s/%s Definitions", release, service)
		bar := pb.StartNew(len(r.Definitions.Definition))
		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu CVE %s/%s Tests", release, service)
		bar = pb.StartNew(len(r.Tests.Textfilecontent54Test))
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu CVE %s/%s Objects", release, service)
		bar = pb.StartNew(len(r.Objects.Textfilecontent54Object))
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu CVE %s/%s States", release, service)
		bar = pb.StartNew(len(r.States.Textfilecontent54State))
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu CVE %s/%s Variables", release, service)
		bar = pb.StartNew(len(r.Variables.ConstantVariable))
		for _, variable := range r.Variables.ConstantVariable {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)), variable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)))
			}
			bar.Increment()
		}
		bar.Finish()
	}

	for name, href := range ovals.PKG {
		release, service, ok := strings.Cut(name, "/")
		if !ok {
			return errors.Errorf("unexpected oval name. expected: \"<release>/<service>\", actual: %q", name)
		}

		log.Printf("[INFO] Fetch Ubuntu PKG %s/%s", release, service)
		r, err := func() (*pkgroot, error) {
			u, err := url.JoinPath(options.baseURL, href)
			if err != nil {
				return nil, errors.Wrap(err, "join url path")
			}

			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch oval")
			}
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var root pkgroot
			if err := xml.NewDecoder(bzip2.NewReader(resp.Body)).Decode(&root); err != nil {
				return nil, errors.Wrap(err, "decode oval")
			}

			return &root, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		log.Printf("[INFO] Fetch Ubuntu PKG %s/%s Definitions", release, service)
		bar := pb.StartNew(len(r.Definitions.Definition))
		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu PKG %s/%s Tests", release, service)
		bar = pb.StartNew(len(r.Tests.Textfilecontent54Test))
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu PKG %s/%s Objects", release, service)
		bar = pb.StartNew(len(r.Objects.Textfilecontent54Object))
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu PKG %s/%s States", release, service)
		bar = pb.StartNew(len(r.States.Textfilecontent54State))
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu PKG %s/%s Variables", release, service)
		bar = pb.StartNew(len(r.Variables.ConstantVariable))
		for _, variable := range r.Variables.ConstantVariable {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)), variable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)))
			}
			bar.Increment()
		}
		bar.Finish()
	}

	for release, href := range ovals.USN {
		log.Printf("[INFO] Fetch Ubuntu USN %s", release)
		r, err := func() (*usnroot, error) {
			u, err := url.JoinPath(options.baseURL, href)
			if err != nil {
				return nil, errors.Wrap(err, "join url path")
			}

			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch oval")
			}
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var root usnroot
			if err := xml.NewDecoder(bzip2.NewReader(resp.Body)).Decode(&root); err != nil {
				return nil, errors.Wrap(err, "decode oval")
			}

			return &root, nil
		}()
		if err != nil {
			return errors.Wrap(err, "fetch")
		}

		log.Printf("[INFO] Fetch Ubuntu USN %s Definitions", release)
		bar := pb.StartNew(len(r.Definitions.Definition))
		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu USN %s Tests", release)
		bar = pb.StartNew(len(r.Tests.Textfilecontent54Test))
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu USN %s Objects", release)
		bar = pb.StartNew(len(r.Objects.Textfilecontent54Object))
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu USN %s States", release)
		bar = pb.StartNew(len(r.States.Textfilecontent54State))
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			bar.Increment()
		}
		bar.Finish()

		log.Printf("[INFO] Fetch Ubuntu USN %s Variables", release)
		bar = pb.StartNew(len(r.Variables.ConstantVariable))
		for _, v := range r.Variables.ConstantVariable {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "variables", "constant_variable", fmt.Sprintf("%s.json", v.ID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "variables", "constant_variable", fmt.Sprintf("%s.json", v.ID)))
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (opts options) walkIndexOf() (ovals, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return ovals{}, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return ovals{}, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ovals{}, errors.Wrap(err, "parse as html")
	}

	ovals := ovals{
		CVE: make(map[string]string),
		PKG: make(map[string]string),
		USN: make(map[string]string),
	}
	d.Find("table").Each(func(_ int, s *goquery.Selection) {
		s.Find("tr").Each(func(i int, r *goquery.Selection) {
			if i == 0 {
				return
			}

			switch r.Find("th").First().Text() {
			case "CVE":
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

						ovals.CVE[release] = f
					default:
						return false
					}
					return true
				})
			case "PKG":
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

						if !strings.HasPrefix(f, "oci.") || !strings.HasSuffix(f, ".pkg.oval.xml.bz2") {
							return false
						}

						ovals.PKG[release] = f
					default:
						return false
					}
					return true
				})
			case "USN":
				var release string
				r.Find("td").EachWithBreak(func(itd int, d *goquery.Selection) bool {
					switch itd {
					case 0:
						release = d.Text()
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

						if !strings.HasPrefix(f, "oci.") || !strings.HasSuffix(f, ".usn.oval.xml.bz2") {
							return false
						}

						ovals.USN[release] = f
					default:
						return false
					}
					return true
				})
			default:
				return
			}
		})
	})
	return ovals, nil
}
