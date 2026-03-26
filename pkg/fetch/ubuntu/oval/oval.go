package oval

import (
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

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

	slog.Info("Fetch Ubuntu OVAL")
	ovals, err := options.walkIndexOf()
	if err != nil {
		return errors.Wrap(err, "walk index of")
	}

	for name, href := range ovals.CVE {
		release, service, ok := strings.Cut(name, "/")
		if !ok {
			return errors.Errorf("unexpected oval name. expected: \"<release>/<service>\", actual: %q", name)
		}

		slog.Info("Fetch Ubuntu CVE OVAL", slog.String("release", release), slog.String("service", service))
		r, err := func() (*cveroot, error) {
			u, err := url.JoinPath(options.baseURL, href)
			if err != nil {
				return nil, errors.Wrap(err, "join url path")
			}

			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch oval")
			}
			defer resp.Body.Close()

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

		slog.Info("Fetch Ubuntu CVE OVAL Definitions", slog.String("release", release), slog.String("service", service))
		bar := progressbar.Default(int64(len(r.Definitions.Definition)))
		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu CVE OVAL Tests", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.Tests.Textfilecontent54Test)))
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu CVE OVAL Objects", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.Objects.Textfilecontent54Object)))
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu CVE OVAL States", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.States.Textfilecontent54State)))
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu CVE OVAL Variables", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.Variables.ConstantVariable)))
		for _, variable := range r.Variables.ConstantVariable {
			if err := util.Write(filepath.Join(options.dir, release, "cve", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)), variable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "cve", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	for name, href := range ovals.PKG {
		release, service, ok := strings.Cut(name, "/")
		if !ok {
			return errors.Errorf("unexpected oval name. expected: \"<release>/<service>\", actual: %q", name)
		}

		slog.Info("Fetch Ubuntu PKG OVAL", slog.String("release", release), slog.String("service", service))
		r, err := func() (*pkgroot, error) {
			u, err := url.JoinPath(options.baseURL, href)
			if err != nil {
				return nil, errors.Wrap(err, "join url path")
			}

			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch oval")
			}
			defer resp.Body.Close()

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

		slog.Info("Fetch Ubuntu PKG OVAL Definitions", slog.String("release", release), slog.String("service", service))
		bar := progressbar.Default(int64(len(r.Definitions.Definition)))
		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu PKG OVAL Tests", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.Tests.Textfilecontent54Test)))
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu PKG OVAL Objects", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.Objects.Textfilecontent54Object)))
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu PKG OVAL States", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.States.Textfilecontent54State)))
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu PKG OVAL Variables", slog.String("release", release), slog.String("service", service))
		bar = progressbar.Default(int64(len(r.Variables.ConstantVariable)))
		for _, variable := range r.Variables.ConstantVariable {
			if err := util.Write(filepath.Join(options.dir, release, "pkg", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)), variable); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "pkg", service, "variables", "constant_variable", fmt.Sprintf("%s.json", variable.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	for release, href := range ovals.USN {
		slog.Info("Fetch Ubuntu USN", slog.String("release", release))
		r, err := func() (*usnroot, error) {
			u, err := url.JoinPath(options.baseURL, href)
			if err != nil {
				return nil, errors.Wrap(err, "join url path")
			}

			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(u)
			if err != nil {
				return nil, errors.Wrap(err, "fetch oval")
			}
			defer resp.Body.Close()

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

		slog.Info("Fetch Ubuntu USN Definitions", slog.String("release", release))
		bar := progressbar.Default(int64(len(r.Definitions.Definition)))
		for _, def := range r.Definitions.Definition {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "definitions", fmt.Sprintf("%s.json", def.ID)), def); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "definitions", fmt.Sprintf("%s.json", def.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu USN Tests", slog.String("release", release))
		bar = progressbar.Default(int64(len(r.Tests.Textfilecontent54Test)))
		for _, test := range r.Tests.Textfilecontent54Test {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)), test); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "tests", "textfilecontent54_test", fmt.Sprintf("%s.json", test.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu USN Objects", slog.String("release", release))
		bar = progressbar.Default(int64(len(r.Objects.Textfilecontent54Object)))
		for _, object := range r.Objects.Textfilecontent54Object {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)), object); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "objects", "textfilecontent54_object", fmt.Sprintf("%s.json", object.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu USN States", slog.String("release", release))
		bar = progressbar.Default(int64(len(r.States.Textfilecontent54State)))
		for _, state := range r.States.Textfilecontent54State {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)), state); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "states", "textfilecontent54_state", fmt.Sprintf("%s.json", state.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()

		slog.Info("Fetch Ubuntu USN Variables", slog.String("release", release))
		bar = progressbar.Default(int64(len(r.Variables.ConstantVariable)))
		for _, v := range r.Variables.ConstantVariable {
			if err := util.Write(filepath.Join(options.dir, release, "usn", "variables", "constant_variable", fmt.Sprintf("%s.json", v.ID)), v); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, release, "usn", "variables", "constant_variable", fmt.Sprintf("%s.json", v.ID)))
			}
			_ = bar.Add(1)
		}
		_ = bar.Close()
	}

	return nil
}

func (opts options) walkIndexOf() (ovals, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(opts.baseURL)
	if err != nil {
		return ovals{}, errors.Wrap(err, "fetch index of")
	}
	defer resp.Body.Close()

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
								slog.Warn("release not found", slog.String("row", ret))
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
							slog.Warn("release not set", slog.String("row", ret))
							return false
						}

						f := d.Find("a").First().Text()
						if f == "" {
							ret, err := r.Html()
							if err != nil {
								ret = fmt.Sprintf("failed to get html. err: %s", err)
							}
							slog.Warn("file name not found", slog.String("row", ret))
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
								slog.Warn("release not found", slog.String("row", ret))
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
							slog.Warn("release not set", slog.String("row", ret))
							return false
						}

						f := d.Find("a").First().Text()
						if f == "" {
							ret, err := r.Html()
							if err != nil {
								ret = fmt.Sprintf("failed to get html. err: %s", err)
							}
							slog.Warn("file name not found", slog.String("row", ret))
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
							slog.Warn("release not set", slog.String("row", ret))
							return false
						}

						f := d.Find("a").First().Text()
						if f == "" {
							ret, err := r.Html()
							if err != nil {
								ret = fmt.Sprintf("failed to get html. err: %s", err)
							}
							slog.Warn("file name not found", slog.String("row", ret))
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
