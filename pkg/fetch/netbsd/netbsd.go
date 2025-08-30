package netbsd

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "https://ftp.netbsd.org/pub/NetBSD/packages/vulns/pkg-vulnerabilities"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "netbsd"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.dataURL)
	if err != nil {
		return errors.Wrap(err, "fetch pkg-vulnerabilities")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	m := make(map[string]Vulnerability)

	// ref. parse_pkg_vuln https://cdn.netbsd.org/pub/pkgsrc/stable/pkgsrc/pkgtools/pkg_install/files/lib/vulnerabilities-file.c
	s := bufio.NewScanner(resp.Body)
LOOP:
	for s.Scan() {
		t := s.Text()
		switch {
		case t == "":
		case strings.HasPrefix(t, "-----BEGIN PGP SIGNED MESSAGE-----"):
		case strings.HasPrefix(t, "Hash:"):
		case strings.HasPrefix(t, "#"):
		case strings.HasPrefix(t, "-----BEGIN PGP SIGNATURE-----"):
			break LOOP
		default:
			ss := strings.Fields(t)
			if len(ss) != 3 {
				return errors.Errorf("unexpected line format. expected: %q, actual: %q", "<package> <type of exploit> <URL>", t)
			}

			v, ok := m[ss[2]]
			if !ok {
				v = Vulnerability{URL: ss[2]}
			}
			v.Packages = append(v.Packages, Package{
				Condition:     ss[0],
				TypeOfExploit: ss[1],
			})
			m[ss[2]] = v
		}
	}
	if err := s.Err(); err != nil {
		return errors.Wrap(err, "scanner encounter error")
	}

	for k, v := range m {
		sum := sha256.Sum256([]byte(k))

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%x", sum[:1]), fmt.Sprintf("%x.json", sum)), v); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%x", sum[:4]), fmt.Sprintf("%x.json", sum)))
		}
	}

	return nil
}
