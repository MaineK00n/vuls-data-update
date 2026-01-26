package updateinfo

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://dl.fedoraproject.org/pub/"

type options struct {
	baseURL     string
	dir         string
	retry       int
	concurrency int
	wait        time.Duration
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

type waitOption time.Duration

func (w waitOption) apply(opts *options) {
	opts.wait = time.Duration(w)
}

func WithWait(wait time.Duration) Option {
	return waitOption(wait)
}

func Fetch(opts ...Option) error {
	options := &options{
		baseURL:     baseURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "fedora", "updateinfo"),
		retry:       3,
		concurrency: 5,
		wait:        1 * time.Second,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Fedora Updateinfo")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	us, err := options.fetchFullFileTimeList(client)
	if err != nil {
		return errors.Wrap(err, "fetch fullfiletimelist")
	}

	if err := options.fetch(client, us); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

func (o options) fetchFullFileTimeList(client *utilhttp.Client) ([]string, error) {
	log.Printf("[INFO] Fetch Fedora fullfiletimelist")

	var us []string

	for _, d := range []string{"fedora", "fedora-secondary", "epel", "archive"} {
		u, err := url.JoinPath(o.baseURL, d, fmt.Sprintf("fullfiletimelist-%s", d))
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}

		resp, err := client.Get(u)
		if err != nil {
			return nil, errors.Wrapf(err, "fetch %s", u)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		// 	```
		// [Version]
		//
		// [Files]
		// 1767700953      f       282     linux/extras/README
		// 1366880149      d       4096    linux/extras
		// 1182178200      d       4096    linux/core/development
		// 1767700953      f       282     linux/core/updates/README
		//
		// [Checksums SHA1]
		//
		// [Checksums MD5]
		//
		// [Checksums SHA256]
		//
		// [Checksums SHA512]
		//
		// [End]
		// ```

		scanner := bufio.NewScanner(resp.Body)
		isFilesSection := false
		for scanner.Scan() {
			s := strings.TrimSpace(scanner.Text())
			switch {
			case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
				switch s {
				case "[Files]":
					isFilesSection = true
				default:
					isFilesSection = false
				}
			default:
				if !isFilesSection || s == "" {
					continue
				}

				fields := strings.Fields(s)
				if len(fields) != 4 {
					return nil, errors.Errorf("unexpected fullfiletimelist Files format. expected: %q, actual: %q", "<unixtime>      <filetype>       <size>    <filepath>", s)
				}
				if strings.HasSuffix(fields[3], "repomd.xml") {
					u, err := url.JoinPath(o.baseURL, d, fields[3])
					if err != nil {
						return nil, errors.Wrap(err, "join url path")
					}
					us = append(us, u)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, errors.Wrap(err, "scanner encounter error")
		}
	}

	return us, nil
}

func (o options) fetch(client *utilhttp.Client, urls []string) error {
	uchan := make(chan string, len(urls))
	go func() {
		defer close(uchan)
		for _, u := range urls {
			uchan <- u
		}
	}()

	bar := progressbar.Default(int64(len(urls)), "fetch repomd -> updateinfo/modules")
	eg, ctx := errgroup.WithContext(context.TODO())
	eg.SetLimit(o.concurrency)
	for i := 0; i < o.concurrency; i++ {
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case u, ok := <-uchan:
					if !ok {
						return nil
					}

					if err := func() error {
						defer func() {
							time.Sleep(o.wait)
							_ = bar.Add(1)
						}()

						// NOTE: In rare cases, after fetching repomd,
						// repodata is updated before fetching updateinfo and modules,
						// and the updateinfo and modules that were being fetched are no longer available.
						// If this occurs frequently, a mechanism to retry from repomd is needed.

						uu, mu, err := o.fetchRepomd(client, u)
						if err != nil {
							return errors.Wrapf(err, "fetch repomd %s", u)
						}

						if uu == "" {
							return nil
						}

						time.Sleep(o.wait)

						if err := o.fetchUpdateinfo(client, uu); err != nil {
							return errors.Wrapf(err, "fetch updateinfo %s", uu)
						}

						if mu == "" {
							return nil
						}

						time.Sleep(o.wait)

						if err := o.fetchModules(client, mu); err != nil {
							return errors.Wrapf(err, "fetch modules %s", mu)
						}

						return nil
					}(); err != nil {
						return errors.Wrap(err, "fetch repomd, updateinfo, modules")
					}
				}
			}
		})
	}
	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "err in goroutine")
	}
	_ = bar.Close()

	return nil
}

func (o options) fetchRepomd(client *utilhttp.Client, u string) (string, string, error) {
	resp, err := client.Get(u)
	if err != nil {
		return "", "", errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r repomd
	if err := xml.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", errors.Wrap(err, "decode xml")
	}

	var uu, mu string
	for _, d := range r.Data {
		switch d.Type {
		case "updateinfo":
			// resp.Request.URL: https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/22/x86_64/repodata/repomd.xml
			// d.Location.Href: repodata/dd69ead4b1b2c1545b0c18b65bb06bb604d8a1becbe9e754da445325cd8dbbf4-updateinfo.xml.xz
			// resolved: https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/22/x86_64/repodata/dd69ead4b1b2c1545b0c18b65bb06bb604d8a1becbe9e754da445325cd8dbbf4-updateinfo.xml.xz

			ref, err := url.Parse(path.Join("..", func() string {
				// zchunk (.zck) format is not supported, so replace it with bz2
				switch strings.TrimPrefix(resp.Request.URL.String(), strings.TrimSuffix(o.baseURL, "/")) {
				case "/archive/epel/6.2017-11-07/SRPMS/repodata/repomd.xml",
					"/archive/epel/6.2017-11-07/i386/repodata/repomd.xml",
					"/archive/epel/6.2017-11-07/x86_64/repodata/repomd.xml":
					switch d.Location.Href {
					case "repodata/cb8e4ee8f3eb2fce514d7f4e10afc1813b390779201667917b45921f483840f8-updateinfo.xml.zck":
						return "repodata/804c7236e6d341cbb68a257bf8b984a140c1f1d2006e35ba9f6d2383b1a50ab0-updateinfo.xml.bz2"
					default:
						return d.Location.Href
					}
				case "/archive/epel/7.2019-05-29/SRPMS/repodata/repomd.xml",
					"/archive/epel/7.2019-05-29/aarch64/repodata/repomd.xml",
					"/archive/epel/7.2019-05-29/ppc64le/repodata/repomd.xml":
					switch d.Location.Href {
					case "repodata/92f2e15cad66d79ea1ad327e2af7af89d98e4d153d7a3e27ff41946f476af5b4-updateinfo.xml.zck":
						return "repodata/aa4b9b1e526d7892647cb665faaa08f6567a0f4249fcd5d85b8e2085ce82a789-updateinfo.xml.bz2"
					default:
						return d.Location.Href
					}
				case "/archive/epel/testing/6.2019-05-29/SRPMS/repodata/repomd.xml",
					"/archive/epel/testing/6.2019-05-29/aarch64/repodata/repomd.xml",
					"/archive/epel/testing/6.2019-05-29/ppc64le/repodata/repomd.xml",
					"/archive/epel/testing/6.2019-05-29/x86_64/repodata/repomd.xml":
					switch d.Location.Href {
					case "repodata/599f65ce6099bfad623b41848a15d878244e1ed75dbc198bb053539d81ebb6a3-updateinfo.xml.zck":
						return "repodata/009e13a53f80786d4bec182ca2f8b45f94802a81b9e09028e69b944933af07e6-updateinfo.xml.bz2"
					default:
						return d.Location.Href
					}
				case "/archive/epel/testing/6.2019-05-29/i386/repodata/repomd.xml":
					switch d.Location.Href {
					case "repodata/4ea3c6885c019b03167b475cd477a6782dc67181e77902f7196cd7cfe37be8fd-updateinfo.xml.zck":
						return "repodata/08e84d912e490a55dd3d0115e63abb40cee70f2651e74ac7bca73a48ee8f6d88-updateinfo.xml.bz2"
					default:
						return d.Location.Href
					}
				default:
					return d.Location.Href
				}
			}()))
			if err != nil {
				return "", "", errors.Wrap(err, "parse url")
			}

			uu = resp.Request.URL.ResolveReference(ref).String()
		case "modules":
			// resp.Request.URL: https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/35/Modular/x86_64/repodata/repomd.xml
			// d.Location.Href: repodata/bff1464c669325bf287c7d89f64aa8c9439aefc8c929812bec203b8dd4abbff2-modules.yaml.gz
			// resolved: https://archives.fedoraproject.org/pub/archive/fedora/linux/updates/35/Modular/x86_64/repodata/bff1464c669325bf287c7d89f64aa8c9439aefc8c929812bec203b8dd4abbff2-modules.yaml.gz

			ref, err := url.Parse(path.Join("..", d.Location.Href))
			if err != nil {
				return "", "", errors.Wrap(err, "parse url")
			}

			mu = resp.Request.URL.ResolveReference(ref).String()
		default:
		}
	}

	return uu, mu, nil
}

func (o options) fetchUpdateinfo(client *utilhttp.Client, u string) error {
	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := toDir(resp.Request.URL.String(), o.baseURL)
	if err != nil {
		return errors.Wrap(err, "to dir")
	}

	buf := new(bytes.Buffer)
	switch {
	case strings.HasSuffix(resp.Request.URL.String(), ".xml"):
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return errors.Wrap(err, "read xml")
		}
	case strings.HasSuffix(resp.Request.URL.String(), ".gz"):
		r, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create gzip reader")
		}
		defer r.Close()

		if _, err := buf.ReadFrom(r); err != nil {
			return errors.Wrap(err, "read gzip")
		}
	case strings.HasSuffix(resp.Request.URL.String(), ".xz"):
		r, err := xz.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create xz reader")
		}

		if _, err := buf.ReadFrom(r); err != nil {
			return errors.Wrap(err, "read xz")
		}
	case strings.HasSuffix(resp.Request.URL.String(), ".bz2"):
		if _, err := buf.ReadFrom(bzip2.NewReader(resp.Body)); err != nil {
			return errors.Wrap(err, "read bzip2")
		}
	case strings.HasSuffix(resp.Request.URL.String(), ".zst"):
		r, err := zstd.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create zstd reader")
		}
		defer r.Close()

		if _, err := buf.ReadFrom(r); err != nil {
			return errors.Wrap(err, "read zstd")
		}
	default:
		return errors.Errorf("unexpected updateinfo fileformat. expected: %q, actual: %q", []string{".xml", ".xml.gz", ".xml.xz", ".xml.bz2", ".xml.zst"}, resp.Request.URL)
	}

	var ui updateinfo
	if err := xml.NewDecoder(buf).Decode(&ui); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	for _, u := range ui.Update {
		ss := strings.Split(u.ID, "-")
		t, err := time.Parse("2006", ss[len(ss)-2])
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "FEDORA-...-<YEAR>-<suffix>", u.ID)
		}

		if err := util.Write(filepath.Join(o.dir, d, t.Format("2006"), fmt.Sprintf("%s.json", u.ID)), u); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, d, t.Format("2006"), fmt.Sprintf("%s.json", u.ID)))
		}
	}

	return nil
}

func (o options) fetchModules(client *utilhttp.Client, u string) error {
	resp, err := client.Get(u)
	if err != nil {
		return errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := toDir(resp.Request.URL.String(), o.baseURL)
	if err != nil {
		return errors.Wrap(err, "to dir")
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer gr.Close()

	scanner := bufio.NewScanner(gr)
	var sb strings.Builder
	for scanner.Scan() {
		switch s := scanner.Text(); s {
		case "---":
			sb.Reset()
		case "...":
			var ms modules
			if err := yaml.Unmarshal([]byte(sb.String()), &ms); err != nil {
				return errors.Wrap(err, "unmarshal yaml")
			}

			switch ms.Document {
			case "modulemd":
				switch ms.Version {
				case 2:
					var md Modulemd
					if err := ms.Data.Decode(&md); err != nil {
						return errors.Wrap(err, "decode yaml")
					}

					if err := util.Write(filepath.Join(o.dir, d, fmt.Sprintf("%s-%s-%d.%s.json", md.Name, md.Stream, md.Version, md.Context)), md); err != nil {
						return errors.Wrapf(err, "write %s", filepath.Join(o.dir, d, fmt.Sprintf("%s-%s-%d.%s.json", md.Name, md.Stream, md.Version, md.Context)))
					}
				default:
					return errors.Errorf("unexpected modulemd version. expected: %q, actual: %q", 2, ms.Version)
				}
			default:
			}
		default:
			sb.WriteString(s)
			sb.WriteString("\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.Wrap(err, "scanner encounter error")
	}

	return nil
}

func toDir(u, baseURL string) (string, error) {
	var ps []string

	after, ok := strings.CutPrefix(u, strings.TrimSuffix(baseURL, "/"))
	if !ok {
		return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", fmt.Sprintf("%s/...", strings.TrimSuffix(baseURL, "/")), u)
	}

	lhs, rhs, ok := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(after, "/"), "archive/"), "/")
	if !ok {
		return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", []string{fmt.Sprintf("%s/(archive/)<os>/...", strings.TrimSuffix(baseURL, "/")), fmt.Sprintf("%s/archive/<os>/...", strings.TrimSuffix(baseURL, "/"))}, u)
	}

	switch lhs {
	case "fedora", "fedora-secondary":
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/core/updates/6/x86_64/repodata/updateinfo.xml.gz : fedora/6/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/core/updates/testing/6/x86_64/repodata/updateinfo.xml.gz : fedora/6/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/27/x86_64/repodata/352c3bcc090f7d6e37e7bac80a259d5682a5baf6967242a0b173b263d7af8cbb-updateinfo.xml.xz : fedora/27/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/27/x86_64/repodata/eaba361c29e430d489e8c9dd3747978be578dffc12ba4b1cf98a8e4904f60ea1-updateinfo.xml.xz : fedora/27/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/35/Everything/x86_64/repodata/35333f73fb5940a299346fd75ea39336644d767bcb7e12b0234458c44ffba38e-updateinfo.xml.xz : fedora/35/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/35/Modular/x86_64/repodata/5a16b438cba15d33c7741b91f17ab2bd1c368669e53c85882d07c6dcc6cb424f-updateinfo.xml.xz : fedora/35/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/35/Everything/x86_64/repodata/c1a94302bc40694f186517c549d982a90fa87460c2f24c2d072e93e284e34c6a-updateinfo.xml.xz : fedora/35/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/35/Modular/x86_64/repodata/e00c2edf41aeffede082bc8f048ef7b037208d4faf8462391c5a3be8a1378268-updateinfo.xml.xz : fedora/35/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/fedora/linux/updates/43/Everything/x86_64/repodata/e09d8b3caedce118e9e23ab4649500c8678cbda905d2bf0c13d81d97895131dc-updateinfo.xml.zst : fedora/43/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/fedora/linux/updates/testing/43/Everything/x86_64/repodata/97333374229a2a64bc8c6b767924453dc5dac3eb2e847921956216428c6494bb-updateinfo.xml.zst : fedora/43/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz : fedora/38/x86_64/modules
		// https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/testing/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz : fedora/38/x86_64/modules

		// https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/27/s390x/repodata/352c3bcc090f7d6e37e7bac80a259d5682a5baf6967242a0b173b263d7af8cbb-updateinfo.xml.xz : fedora/27/s390x/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/27/s390x/repodata/eaba361c29e430d489e8c9dd3747978be578dffc12ba4b1cf98a8e4904f60ea1-updateinfo.xml.xz : fedora/27/s390x/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/35/Everything/s390x/repodata/c1a94302bc40694f186517c549d982a90fa87460c2f24c2d072e93e284e34c6a-updateinfo.xml.xz : fedora/35/s390x/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/35/Modular/s390x/repodata/e00c2edf41aeffede082bc8f048ef7b037208d4faf8462391c5a3be8a1378268-updateinfo.xml.xz : fedora/35/s390x/updateinfo
		// https://dl.fedoraproject.org/pub/fedora-secondary/updates/43/Everything/s390x/repodata/74f58a91baa4a290e7ab058c6298b46ef49fc5ee990ede14d181340e5d22fca9-updateinfo.xml.zst : fedora/43/s390x/updateinfo
		// https://dl.fedoraproject.org/pub/fedora-secondary/updates/testing/43/Everything/s390x/repodata/97333374229a2a64bc8c6b767924453dc5dac3eb2e847921956216428c6494bb-updateinfo.xml.zst : fedora/43/s390x/updateinfo
		// https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/38/Modular/s390x/repodata/79fd8acbc78883e6c31dc79f0c595d198445143081d4b50d4e295e718a088ba8-modules.yaml.gz : fedora/38/s390x/modules
		// https://dl.fedoraproject.org/pub/archive/fedora-secondary/updates/testing/38/Modular/s390x/repodata/79fd8acbc78883e6c31dc79f0c595d198445143081d4b50d4e295e718a088ba8-modules.yaml.gz : fedora/38/s390x/modules

		ps = append(ps, "fedora")

		ss := slices.DeleteFunc(strings.Split(rhs, "/"), func(e string) bool { return e == "testing" })
		i := slices.Index(ss, "updates")
		if i == -1 || i+1 >= len(ss) {
			return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", ".../fedora(-secondary)/linux/.../updates(/testing)/<version>/...", u)
		}
		ps = append(ps, ss[i+1])

		i = slices.Index(ss, "repodata")
		if i == -1 || i-1 < 0 {
			return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", ".../fedora(-secondary)/linux/.../updates(/testing)/<version>/.../<arch>/repodata/...", u)
		}
		ps = append(ps, ss[i-1])

		switch {
		case strings.Contains(ss[len(ss)-1], "updateinfo.xml"):
			ps = append(ps, "updateinfo")
		case strings.Contains(ss[len(ss)-1], "-modules.yaml"):
			ps = append(ps, "modules")
		default:
			return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", ".../fedora(-secondary)/linux/.../updates(/testing)/<version>/.../<arch>/repodata/*(updateinfo.xml|-modules.yaml)...", u)
		}

		return filepath.Join(ps...), nil
	case "epel":
		// https://dl.fedoraproject.org/pub/archive/epel/7/x86_64/repodata/ee7ce72544e0fca006120c613404d937cc3da9d09c7d80aea269df31639f310c-updateinfo.xml.bz2 : epel/7/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/repodata/a4f5e8b54d8034a5ddb28be23feb2ecad0c81b9d0ed51c4c40a29b1171a9aced-updateinfo.xml.bz2 : epel/8/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/epel/testing/8/Everything/x86_64/repodata/0a9cae41db14e597a17a547b2a0520c7dcd4524092ddba1af60e8700e95a4a8d-updateinfo.xml.bz2 : epel/8/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/epel/next/9/Everything/x86_64/repodata/033a4114a1165553d7fb0abb26a1be367270768874fff3129416cbd65e5b2bc7-updateinfo.xml.bz2 : epel-next/9/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/epel/testing/next/9/Everything/x86_64/repodata/93cf4560670e3bf30f62255ef8e20496f66893f6ce5f9930c5502037508a1e70-updateinfo.xml.bz2 : epel-next/9/x86_64/updateinfo
		// https://dl.fedoraproject.org/pub/epel/8/Modular/x86_64/repodata/b1b3a6319d69628902d5b3997fe97e335933d5567f94a49b3692b1226f7c2adc-modules.yaml.gz : epel/8/x86_64/modules
		// https://dl.fedoraproject.org/pub/epel/testing/8/Modular/x86_64/repodata/b1b3a6319d69628902d5b3997fe97e335933d5567f94a49b3692b1226f7c2adc-modules.yaml.gz : epel/8/x86_64/modules

		ss := slices.DeleteFunc(strings.Split(rhs, "/"), func(e string) bool { return e == "testing" })

		repo := "epel"
		i := slices.Index(ss, "next")
		if i != -1 {
			repo = "epel-next"
		}
		ps = append(ps, repo)

		if i+1 >= len(ss) {
			return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", ".../epel/(testing/)(next/)<version>/...", u)
		}
		ps = append(ps, ss[i+1])

		i = slices.Index(ss, "repodata")
		if i == -1 || i-1 < 0 {
			return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", ".../epel/(testing/)(next/)<version>/.../<arch>/repodata/...", u)
		}
		ps = append(ps, ss[i-1])

		switch {
		case strings.Contains(ss[len(ss)-1], "updateinfo.xml"):
			ps = append(ps, "updateinfo")
		case strings.Contains(ss[len(ss)-1], "-modules.yaml"):
			ps = append(ps, "modules")
		default:
			return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", ".../epel/(testing/)(next/)<version>/.../<arch>/repodata/*(updateinfo.xml|-modules.yaml)...", u)
		}

		return filepath.Join(ps...), nil
	default:
		return "", errors.Errorf("unexpected os type. expected: %q, actual: %q", []string{"fedora", "fedora-secondary", "epel"}, lhs)
	}
}
