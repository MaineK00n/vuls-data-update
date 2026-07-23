package updateinfo

import (
	"bufio"
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

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const baseURL = "https://dl.rockylinux.org/"

// trees are the top-level directories of dl.rockylinux.org that ship RPM
// repodata (and thus updateinfo/modules), each paired with the basename of the
// fullfiletimelist manifest that indexes it (the manifest lives directly under
// dir). The current distribution and its Special Interest Group repos live under
// pub/, all end-of-life snapshots under vault/. dir is the path prefix that the
// manifest's relative entries extend; a single vault/fullfiletimelist-vault
// covers both vault/rocky and vault/sig, so its dir is "vault". Unlike
// fedora-updateinfo the manifest names are not uniform (pub/* use the plain
// "fullfiletimelist", vault uses "fullfiletimelist-vault"), so each tree carries
// its manifest basename explicitly.
var trees = []struct {
	dir      string
	manifest string
}{
	{dir: "pub/rocky", manifest: "fullfiletimelist"},
	{dir: "pub/sig", manifest: "fullfiletimelist"},
	{dir: "vault", manifest: "fullfiletimelist-vault"},
}

// isKnownDanglingRef reports whether u is a repodata file that a repomd.xml
// references but which is absent from the mirror — a dangling reference frozen
// into an archived vault snapshot (all listed here are Rocky 8.6 kickstart repos
// whose declared updateinfo has no file present at all, verified 404). These are
// dropped in fetchRepomd so the file is skipped; any other missing file still
// 404s and fails loudly, so a newly-appearing dangling reference can be added
// after verification. vault is frozen, so the set is stable.
func isKnownDanglingRef(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	switch path.Clean(p.Path) {
	case "/vault/rocky/8.6/HighAvailability/aarch64/kickstart/repodata/ad677747a8d80f3f3f5f6ccfaf15dd3a992c6f2341207c2f58c0dcab1e25e044-updateinfo.xml.gz",
		"/vault/rocky/8.6/HighAvailability/x86_64/kickstart/repodata/ad677747a8d80f3f3f5f6ccfaf15dd3a992c6f2341207c2f58c0dcab1e25e044-updateinfo.xml.gz",
		"/vault/rocky/8.6/NFV/aarch64/kickstart/repodata/ad677747a8d80f3f3f5f6ccfaf15dd3a992c6f2341207c2f58c0dcab1e25e044-updateinfo.xml.gz",
		"/vault/rocky/8.6/NFV/x86_64/kickstart/repodata/29a22b48118310a1d7e1f4c5f5906e7be99a19c7eb0d3c779ea4ea9fdcb50181-updateinfo.xml.gz",
		"/vault/rocky/8.6/ResilientStorage/aarch64/kickstart/repodata/ad677747a8d80f3f3f5f6ccfaf15dd3a992c6f2341207c2f58c0dcab1e25e044-updateinfo.xml.gz",
		"/vault/rocky/8.6/ResilientStorage/x86_64/kickstart/repodata/ad677747a8d80f3f3f5f6ccfaf15dd3a992c6f2341207c2f58c0dcab1e25e044-updateinfo.xml.gz",
		"/vault/rocky/8.6/RT/x86_64/kickstart/repodata/3f851aab6522f26ab8f7e912ff74b62831df3f662ef7596e681628da678054c9-updateinfo.xml.gz":
		return true
	default:
		return false
	}
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
		dir:         filepath.Join(util.CacheDir(), "fetch", "rocky", "updateinfo"),
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

	slog.Info("Fetch Rocky Linux Updateinfo")
	client := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry))

	us, err := options.fetchFullFileTimeList(client)
	if err != nil {
		return errors.Wrap(err, "fetch fullfiletimelist")
	}
	slog.Info("Fetch Rocky Linux repomd list done", slog.Int("count", len(us)))

	if err := options.fetch(client, us); err != nil {
		return errors.Wrap(err, "fetch")
	}

	return nil
}

// fetchFullFileTimeList fetches each tree's fullfiletimelist manifest and returns
// the repomd.xml URL of every repository indexed in it. Using the manifest keeps
// discovery to one request per tree instead of walking the directory tree, and
// the manifest is authoritative so no HTML index parsing or depth safeguard is
// needed.
func (o options) fetchFullFileTimeList(client *utilhttp.Client) ([]string, error) {
	slog.Info("Fetch Rocky Linux fullfiletimelist")

	var us []string
	for _, t := range trees {
		mu, err := url.JoinPath(o.baseURL, t.dir, t.manifest)
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}

		resp, err := client.Get(mu)
		if err != nil {
			return nil, errors.Wrapf(err, "fetch %s", mu)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
		}

		// 	```
		// [Version]
		// 2
		//
		// [Files]
		// 1779964652	f	3194	rocky/10.1/devel/ppc64le/os/repodata/repomd.xml
		// 1779964652	d	6144	rocky/10.1/devel/ppc64le/os/repodata
		//
		// [Checksums SHA256]
		//
		// [End]
		// 	```
		//
		// Entries are relative to t.dir (the manifest's directory).
		scanner := bufio.NewScanner(resp.Body)
		isFilesSection := false
		for scanner.Scan() {
			switch s := strings.TrimSpace(scanner.Text()); {
			case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
				isFilesSection = s == "[Files]"
			default:
				if !isFilesSection || s == "" {
					continue
				}

				fields := strings.Fields(s)
				if len(fields) != 4 {
					return nil, errors.Errorf("unexpected fullfiletimelist Files format. expected: %q, actual: %q", "<unixtime>\t<filetype>\t<size>\t<filepath>", s)
				}
				if strings.HasSuffix(fields[3], "repomd.xml") {
					r, err := url.JoinPath(o.baseURL, t.dir, fields[3])
					if err != nil {
						return nil, errors.Wrap(err, "join url path")
					}
					us = append(us, r)
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

						uu, mu, err := o.fetchRepomd(client, u)
						if err != nil {
							return errors.Wrapf(err, "fetch repomd %s", u)
						}

						// uu/mu are independent: a repomd may declare only one of
						// updateinfo/modules, and a dangling reference blanks just that
						// one, so fetch whichever is present without skipping the other.
						if uu != "" {
							time.Sleep(o.wait)

							if err := o.fetchUpdateinfo(client, uu); err != nil {
								return errors.Wrapf(err, "fetch updateinfo %s", uu)
							}
						}

						if mu != "" {
							time.Sleep(o.wait)

							if err := o.fetchModules(client, mu); err != nil {
								return errors.Wrapf(err, "fetch modules %s", mu)
							}
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

	// The manifest listed this repomd.xml, so anything but 200 is a manifest/reality
	// mismatch. Fail loudly rather than skip: a systematic non-200 (e.g. a wrong URL
	// prefix) would otherwise silently yield an empty dataset. Matches fedora-updateinfo.
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var r repomd
	if err := xml.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", errors.Wrap(err, "decode xml")
	}

	// Resolve hrefs against the requested URL, not resp.Request.URL: an end-of-life
	// tree (e.g. dl.rockylinux.org/vault) may redirect to another location that
	// drops the tree path segment. Keeping the logical dl.rockylinux.org URL lets
	// toDir mirror the source layout while the HTTP client still follows the
	// redirect when the bytes are actually fetched.
	base, err := url.Parse(u)
	if err != nil {
		return "", "", errors.Wrap(err, "parse url")
	}

	var uu, mu string
	for _, d := range r.Data {
		// base: https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/repomd.xml
		// d.Location.Href: repodata/<hash>-updateinfo.xml.gz
		// resolved: https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/<hash>-updateinfo.xml.gz
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

	// A repomd.xml can reference an updateinfo/modules file that is absent from
	// the mirror (a dangling reference frozen into an archived vault snapshot).
	// Drop only the known-dangling ones so the file is skipped; any other missing
	// file still 404s in fetchUpdateinfo/fetchModules and fails loudly.
	if isKnownDanglingRef(uu) {
		slog.Warn("skipping known dangling reference in repomd", slog.String("url", uu))
		uu = ""
	}
	if isKnownDanglingRef(mu) {
		slog.Warn("skipping known dangling reference in repomd", slog.String("url", mu))
		mu = ""
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
	// dl.rockylinux.org layout. The filename suffix is identical either way.
	d, err := toDir(u, o.baseURL)
	if err != nil {
		return errors.Wrap(err, "to dir")
	}

	dr, err := decompress(u, resp.Body)
	if err != nil {
		return errors.Wrap(err, "decompress")
	}
	defer dr.Close()

	var ui updateinfo
	if err := xml.NewDecoder(dr).Decode(&ui); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	for _, u := range ui.Update {
		// Group advisories under <prefix>/<year>/ (RLSA/RLBA/RLEA-<year>:<seq>),
		// matching the rocky-errata layout. An ID that does not fit is an
		// unexpected format we do not understand: fail loudly rather than write
		// it somewhere unvalidated and let it flow into extract unnoticed.
		splitted, err := util.Split(u.ID, "-", ":")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "<prefix>-yyyy:<sequence>", u.ID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "<prefix>-yyyy:<sequence>", u.ID)
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

	dr, err := decompress(u, resp.Body)
	if err != nil {
		return errors.Wrap(err, "decompress")
	}
	defer dr.Close()

	scanner := bufio.NewScanner(dr)
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

// decompress returns a reader over the (optionally compressed) body of a repodata
// file, selecting the decoder from the URL suffix. Rocky Linux ships updateinfo as
// *.xml.gz but modules as *.yaml.xz, and mirrors may re-compress with other
// algorithms, so both callers share this format handling. The result streams (it
// does not buffer the whole payload) and must be closed by the caller.
func decompress(u string, r io.Reader) (io.ReadCloser, error) {
	// Match the suffix case-insensitively: some Rocky repositories publish
	// upper-cased repodata filenames (e.g. <hash>-UPDATEINFO.xml.gz).
	switch lu := strings.ToLower(u); {
	case strings.HasSuffix(lu, ".xml"), strings.HasSuffix(lu, ".yaml"):
		return io.NopCloser(r), nil
	case strings.HasSuffix(lu, ".gz"):
		gr, err := gzip.NewReader(r)
		if err != nil {
			return nil, errors.Wrap(err, "create gzip reader")
		}
		return gr, nil
	case strings.HasSuffix(lu, ".xz"):
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, errors.Wrap(err, "create xz reader")
		}
		return io.NopCloser(xr), nil
	case strings.HasSuffix(lu, ".bz2"):
		return io.NopCloser(bzip2.NewReader(r)), nil
	case strings.HasSuffix(lu, ".zst"):
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, errors.Wrap(err, "create zstd reader")
		}
		return zr.IOReadCloser(), nil
	default:
		return nil, errors.Errorf("unexpected fileformat. expected: %q, actual: %q", []string{".xml", ".yaml", ".gz", ".xz", ".bz2", ".zst"}, u)
	}
}

// toDir maps a repodata file URL to the on-disk directory that mirrors its
// source path, replacing the trailing "repodata/<file>" with "updateinfo" or
// "modules". The full source prefix (tree/version/repository/arch/variant) is
// preserved so that os/, kickstart/ and debug/ repositories do not collide.
//
//	https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/<hash>-updateinfo.xml.gz -> pub/rocky/9/BaseOS/x86_64/os/updateinfo
//	https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/repodata/<hash>-modules.yaml.xz -> pub/rocky/9/AppStream/x86_64/os/modules
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

	// Classify case-insensitively: some Rocky repositories publish upper-cased
	// repodata filenames (e.g. <hash>-UPDATEINFO.xml.gz in a few SIG repos).
	switch name := strings.ToLower(ss[len(ss)-1]); {
	case strings.Contains(name, "updateinfo.xml"):
		ps = append(ps, "updateinfo")
	case strings.Contains(name, "-modules.yaml"):
		ps = append(ps, "modules")
	default:
		return "", errors.Errorf("unexpected url format. expected: %q, actual: %q", fmt.Sprintf("%s/<tree>/.../repodata/*(updateinfo.xml|-modules.yaml)...", strings.TrimSuffix(baseURL, "/")), u)
	}

	return filepath.Join(ps...), nil
}
