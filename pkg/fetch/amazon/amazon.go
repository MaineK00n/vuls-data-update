package amazon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type options struct {
	mirrorURLs map[string]MirrorURL
	dir        string
	retry      int
}

type MirrorURL struct {
	Core  string
	Extra string
	extra []string
}

type Option interface {
	apply(*options)
}

type mirrorURLsOption map[string]MirrorURL

func (m mirrorURLsOption) apply(opts *options) {
	opts.mirrorURLs = m
}

func WithMirrorURLs(u map[string]MirrorURL) Option {
	return mirrorURLsOption(u)
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
		mirrorURLs: map[string]MirrorURL{
			"1": {Core: "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"},
			"2": {
				Core:  "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
				Extra: "http://amazonlinux.default.amazonaws.com/2/extras-catalog.json",
			},
			"2022": {Core: "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/x86_64/mirror.list"},
			"2023": {Core: "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list"},
		},
		dir:   filepath.Join(util.SourceDir(), "amazon"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	for v := range options.mirrorURLs {
		log.Printf("[INFO] Fetch Amazon Linux %s", v)
		switch v {
		case "1", "2022", "2023":
		case "2":
			bs, err := util.FetchURL(options.mirrorURLs[v].Extra, options.retry)
			if err != nil {
				return errors.Wrapf(err, "fetch %s", options.mirrorURLs[v].Extra)
			}

			var c catalog
			if err := json.Unmarshal(bs, &c); err != nil {
				return errors.Wrap(err, "unmarshal json")
			}

			m := options.mirrorURLs[v]
			for _, t := range c.Topics {
				m.extra = append(m.extra, strings.Replace(options.mirrorURLs[v].Core, "/core/", fmt.Sprintf("/extras/%s/", t.N), 1))
			}
			options.mirrorURLs[v] = m
		default:
			return errors.Errorf("unexpected version. accepts %q, received %q", []string{"1", "2", "2022", "2023"}, v)
		}

		advs := map[string][]Update{}
		us, err := options.fetch(options.mirrorURLs[v].Core)
		if err != nil {
			return errors.Wrapf(err, "fetch %s", options.mirrorURLs[v].Core)
		}

		advs[getPackageRepository(options.mirrorURLs[v].Core)] = us

		for _, e := range options.mirrorURLs[v].extra {
			us, err := options.fetch(e)
			if err != nil {
				return errors.Wrapf(err, "fetch %s", e)
			}
			if us != nil {
				advs[getPackageRepository(e)] = us
			}
		}

		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		for r, us := range advs {
			log.Printf("[INFO] Fetched Amazon Linux %s %s", v, r)
			bar := pb.StartNew(len(us))
			for _, u := range us {
				ss := strings.Split(u.ID, "-")
				y := ss[len(ss)-2]
				if _, err := strconv.Atoi(y); err != nil {
					continue
				}

				if err := util.Write(filepath.Join(dir, r, y, fmt.Sprintf("%s.json", u.ID)), u); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(dir, r, y, fmt.Sprintf("%s.json", u.ID)))
				}

				bar.Increment()
			}
			bar.Finish()
		}
	}

	return nil
}

func (opts options) fetch(mirror string) ([]Update, error) {
	bs, err := util.FetchURL(mirror, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch mirror list")
	}

	var mirrors []string
	scanner := bufio.NewScanner(bytes.NewReader(bs))
	for scanner.Scan() {
		mirrors = append(mirrors, scanner.Text())
	}

	var updates []Update
	for _, mirror := range mirrors {
		u, err := url.JoinPath(mirror, "/repodata/repomd.xml")
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}
		uinfoPath, err := opts.fetchUpdateInfoPath(u)
		if err != nil {
			if strings.Contains(mirror, "/extras/") && errors.Is(err, ErrNoUpdateInfo) {
				return nil, nil
			}
			return nil, errors.Wrap(err, "fetch updateinfo path")
		}

		u, err = url.JoinPath(mirror, uinfoPath)
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}
		us, err := opts.fetchUpdateInfo(u)
		if err != nil {
			return nil, errors.Wrap(err, "fetch updateinfo")
		}
		updates = append(updates, us...)
	}
	return updates, nil
}

var ErrNoUpdateInfo = errors.New("no updateinfo field")

func (opts options) fetchUpdateInfoPath(repomdURL string) (string, error) {
	bs, err := util.FetchURL(repomdURL, opts.retry)
	if err != nil {
		return "", errors.Wrap(err, "fetch repomd")
	}

	var repomd repomd
	if err := xml.Unmarshal(bs, &repomd); err != nil {
		return "", errors.Wrap(err, "unmarshal repomd.xml")
	}

	var updateInfoPath string
	for _, d := range repomd.Data {
		if d.Type == "updateinfo" {
			updateInfoPath = d.Location.Href
			break
		}
	}
	if updateInfoPath == "" {
		return "", ErrNoUpdateInfo
	}
	return updateInfoPath, nil
}

func (opts options) fetchUpdateInfo(updateinfoURL string) ([]Update, error) {
	bs, err := util.FetchURL(updateinfoURL, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch updateinfo")
	}

	gr, err := gzip.NewReader(bytes.NewReader(bs))
	if err != nil {
		return nil, errors.Wrap(err, "open updateinfo as gzip")
	}
	defer gr.Close()

	var us updates
	if err := xml.NewDecoder(gr).Decode(&us); err != nil {
		return nil, errors.Wrap(err, "decode updateinfo xml")
	}
	return us.Update, nil
}

func getPackageRepository(mirror string) string {
	switch {
	case strings.Contains(mirror, "/updates/"):
		return "updates"
	case strings.Contains(mirror, "/core/"):
		return "core"
	case strings.Contains(mirror, "/extras/"):
		_, rhs, _ := strings.Cut(mirror, "/extras/")
		lhs, _, found := strings.Cut(rhs, "/")
		if !found {
			log.Printf("WARN: failed to find repository. mirror: %s", mirror)
			return "unknown"
		}
		return filepath.Join("extras", lhs)
	default:
		log.Printf("WARN: failed to find repository. mirror: %s", mirror)
		return "unknown"
	}
}
