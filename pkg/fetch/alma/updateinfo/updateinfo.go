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
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://repo.almalinux.org/"

// maxDepth bounds the directory walk as a safeguard against unexpectedly deep
// (or cyclic) trees. Distribution repodata lives at most ~6 levels below a tree
// root (<version>/<repository>/<arch>/<variant>/repodata).
const maxDepth = 16

// trees are the top-level distribution trees of repo.almalinux.org that ship
// RPM repodata (and thus updateinfo/modules). Non-distribution trees
// (build_system, development, security's oval/ltp, elevate, rpi, wsl) are left
// out. Each tree is walked depth-agnostically until a repodata/ directory is
// found, so differing layouts (e.g. almalinux/<v>/<repo>/<arch>/os/repodata vs
// almalinux-epel/<v>/<arch>/repodata) are handled structurally.
var trees = []string{
	"almalinux",
	"vault",
	"almalinux-epel",
	"almalinux-kitten",
	"almalinux-nvidia",
	"backports",
}

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
		dir:         filepath.Join(util.CacheDir(), "fetch", "alma", "updateinfo"),
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

	slog.Info("Fetch AlmaLinux Updateinfo")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	us, err := options.listRepomds(client)
	if err != nil {
		return errors.Wrap(err, "list repomd")
	}
	slog.Info("Fetch AlmaLinux repomd list done", slog.Int("count", len(us)))

	if err := options.fetch(client, us); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

// listRepomds walks each configured tree breadth-first, descending directories
// until it reaches a repodata/ directory, and returns the repomd.xml URL of
// every repository found. The walk is depth-agnostic so it adapts to layout and
// architecture differences without hardcoded version/arch lists.
func (o options) listRepomds(client *utilhttp.Client) ([]string, error) {
	slog.Info("Fetch AlmaLinux repomd list")

	var frontier []string
	for _, tree := range trees {
		u, err := url.JoinPath(o.baseURL, tree)
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}
		frontier = append(frontier, u)
	}

	var repomds []string
	for depth := 0; len(frontier) > 0 && depth < maxDepth; depth++ {
		type result struct {
			repomd   string
			children []string
		}
		results := make([]result, len(frontier))

		eg, ctx := errgroup.WithContext(context.TODO())
		eg.SetLimit(o.concurrency)
		for i, u := range frontier {
			eg.Go(func() error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				dirs, err := o.listDirs(client, u)
				if err != nil {
					return errors.Wrapf(err, "list %s", u)
				}

				if slices.Contains(dirs, "repodata") {
					r, err := url.JoinPath(u, "repodata", "repomd.xml")
					if err != nil {
						return errors.Wrap(err, "join url path")
					}
					results[i] = result{repomd: r}
					return nil
				}

				children := make([]string, 0, len(dirs))
				for _, d := range dirs {
					c, err := url.JoinPath(u, d)
					if err != nil {
						return errors.Wrap(err, "join url path")
					}
					children = append(children, c)
				}
				results[i] = result{children: children}
				return nil
			})
		}
		if err := eg.Wait(); err != nil {
			return nil, errors.Wrap(err, "err in goroutine")
		}

		var next []string
		for _, r := range results {
			if r.repomd != "" {
				repomds = append(repomds, r.repomd)
			}
			next = append(next, r.children...)
		}
		frontier = next

		slog.Info("Walk", slog.String("baseURL", o.baseURL), slog.Int("depth", depth), slog.Int("dirs", len(results)), slog.Int("repomds", len(repomds)))
	}

	// Reaching maxDepth with directories still pending is not a per-item skip but
	// a traversal that did not complete: the tree is deeper than any known layout
	// or is cyclic (e.g. a self-referential symlink). Fail loudly rather than
	// silently returning an incomplete repomd set.
	if len(frontier) > 0 {
		return nil, errors.Errorf("walk reached max depth %d with %d directories still pending; %s tree is deeper than expected or cyclic", maxDepth, len(frontier), strings.TrimSuffix(o.baseURL, "/"))
	}

	return repomds, nil
}

// listDirs returns the subdirectory names (without trailing slash) linked from
// the HTML index at u. A missing directory (404) yields no entries so that a
// non-existent tree or a vanished directory is skipped rather than failing.
func (o options) listDirs(client *utilhttp.Client, u string) ([]string, error) {
	resp, err := client.Get(u)
	if err != nil {
		return nil, errors.Wrapf(err, "fetch %s", u)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	d, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "parse as html")
	}

	var dirs []string
	d.Find("a").Each(func(_ int, selection *goquery.Selection) {
		txt := strings.TrimSpace(selection.Text())
		name, ok := strings.CutSuffix(txt, "/")
		if !ok || name == "" || name == "." || name == ".." {
			return
		}
		dirs = append(dirs, name)
	})
	return dirs, nil
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

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// The repodata directory was listed but repomd.xml is missing (e.g. a
		// concurrent repodata refresh). Skip instead of failing the whole run.
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", "", nil
	default:
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r repomd
	if err := xml.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", errors.Wrap(err, "decode xml")
	}

	// Resolve hrefs against the requested URL, not resp.Request.URL: some trees
	// (e.g. repo.almalinux.org/vault) redirect to another host (vault.almalinux.org)
	// that drops the tree path segment. Keeping the logical repo.almalinux.org URL
	// lets toDir mirror the source layout while the HTTP client still follows the
	// redirect when the bytes are actually fetched.
	base, err := url.Parse(u)
	if err != nil {
		return "", "", errors.Wrap(err, "parse url")
	}

	var uu, mu string
	for _, d := range r.Data {
		// base: https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/repodata/repomd.xml
		// d.Location.Href: repodata/<hash>-updateinfo.xml.gz
		// resolved: https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/repodata/<hash>-updateinfo.xml.gz
		switch d.Type {
		case "updateinfo":
			ref, err := url.Parse(path.Join("..", d.Location.Href))
			if err != nil {
				return "", "", errors.Wrap(err, "parse url")
			}
			uu = base.ResolveReference(ref).String()
		case "modules":
			ref, err := url.Parse(path.Join("..", d.Location.Href))
			if err != nil {
				return "", "", errors.Wrap(err, "parse url")
			}
			mu = base.ResolveReference(ref).String()
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

	// Use the requested (logical) URL rather than resp.Request.URL for the output
	// path and format detection, so that redirected trees still mirror their
	// repo.almalinux.org layout. The filename suffix is identical either way.
	d, err := toDir(u, o.baseURL)
	if err != nil {
		return errors.Wrap(err, "to dir")
	}

	buf := new(bytes.Buffer)
	switch {
	case strings.HasSuffix(u, ".xml"):
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return errors.Wrap(err, "read xml")
		}
	case strings.HasSuffix(u, ".gz"):
		r, err := gzip.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create gzip reader")
		}
		defer r.Close()

		if _, err := buf.ReadFrom(r); err != nil {
			return errors.Wrap(err, "read gzip")
		}
	case strings.HasSuffix(u, ".xz"):
		r, err := xz.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create xz reader")
		}

		if _, err := buf.ReadFrom(r); err != nil {
			return errors.Wrap(err, "read xz")
		}
	case strings.HasSuffix(u, ".bz2"):
		if _, err := buf.ReadFrom(bzip2.NewReader(resp.Body)); err != nil {
			return errors.Wrap(err, "read bzip2")
		}
	case strings.HasSuffix(u, ".zst"):
		r, err := zstd.NewReader(resp.Body)
		if err != nil {
			return errors.Wrap(err, "create zstd reader")
		}
		defer r.Close()

		if _, err := buf.ReadFrom(r); err != nil {
			return errors.Wrap(err, "read zstd")
		}
	default:
		return errors.Errorf("unexpected updateinfo fileformat. expected: %q, actual: %q", []string{".xml", ".xml.gz", ".xml.xz", ".xml.bz2", ".xml.zst"}, u)
	}

	var ui updateinfo
	if err := xml.NewDecoder(buf).Decode(&ui); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	for _, u := range ui.Update {
		// Group advisories under <prefix>/<year>/ (ALSA/ALBA/ALEA-<year>:<seq>),
		// matching the alma-errata layout. An ID that does not fit is an
		// unexpected format we do not understand: fail loudly rather than write
		// it somewhere unvalidated and let it flow into extract unnoticed.
		splitted, err := util.Split(u.ID, "-", ":")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(ALSA|ALBA|ALEA)-yyyy:<sequence>", u.ID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "(ALSA|ALBA|ALEA)-yyyy:<sequence>", u.ID)
		}

		if err := util.Write(filepath.Join(o.dir, d, splitted[0], splitted[1], fmt.Sprintf("%s.json", u.ID)), u); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(o.dir, d, splitted[0], splitted[1], fmt.Sprintf("%s.json", u.ID)))
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

	d, err := toDir(u, o.baseURL)
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
					return errors.Errorf("unexpected modulemd version. expected: %q, actual: %q", "2", fmt.Sprintf("%d", ms.Version))
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

// toDir maps a repodata file URL to the on-disk directory that mirrors its
// source path, replacing the trailing "repodata/<file>" with "updateinfo" or
// "modules". The full source prefix (tree/version/repository/arch/variant) is
// preserved so that os/, kickstart/ and debug/ repositories do not collide.
//
//	https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/repodata/<hash>-updateinfo.xml.gz -> almalinux/9/BaseOS/x86_64/os/updateinfo
//	https://repo.almalinux.org/almalinux-epel/10/x86_64_v2/repodata/<hash>-modules.yaml.gz    -> almalinux-epel/10/x86_64_v2/modules
func toDir(u, baseURL string) (string, error) {
	after, ok := strings.CutPrefix(u, strings.TrimSuffix(baseURL, "/"))
	if !ok {
		return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", fmt.Sprintf("%s/...", strings.TrimSuffix(baseURL, "/")), u)
	}

	ss := strings.Split(strings.TrimPrefix(after, "/"), "/")
	i := slices.Index(ss, "repodata")
	if i < 1 {
		return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", fmt.Sprintf("%s/<tree>/.../repodata/...", strings.TrimSuffix(baseURL, "/")), u)
	}

	// Guard against dot-segments so a crafted URL cannot escape options.dir via
	// filepath.Join path traversal. Callers currently pass URLs already cleaned
	// by url.ResolveReference, but toDir must not rely on that invariant.
	ps := append([]string{}, ss[:i]...)
	for _, p := range ps {
		if p == "." || p == ".." {
			return "", errors.Errorf("unexpected dot-segment %q in url: %q", p, u)
		}
	}

	switch name := ss[len(ss)-1]; {
	case strings.Contains(name, "updateinfo.xml"):
		ps = append(ps, "updateinfo")
	case strings.Contains(name, "-modules.yaml"):
		ps = append(ps, "modules")
	default:
		return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", fmt.Sprintf("%s/<tree>/.../repodata/*(updateinfo.xml|-modules.yaml)...", strings.TrimSuffix(baseURL, "/")), u)
	}

	return filepath.Join(ps...), nil
}
