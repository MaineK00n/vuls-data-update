package amazon

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/schollz/progressbar/v3"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

type options struct {
	mirrorURLs map[string]MirrorURL
	dir        string
	retry      int
}

type MirrorURL struct {
	Core            string
	Extra           string
	extra           []string
	KernelLivePatch string
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
				Extra: "https://cdn.amazonlinux.com/2/extras-catalog.json",
			},
			"2022": {
				Core: "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/x86_64/mirror.list",
			},
			"2023": {
				Core:            "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
				KernelLivePatch: "https://cdn.amazonlinux.com/al2023/kernel-livepatch/mirrors/latest/x86_64/mirror.list",
			},
		},
		dir:   filepath.Join(util.CacheDir(), "fetch", "amazon"),
		retry: 3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	for v := range options.mirrorURLs {
		log.Printf("[INFO] Fetch Amazon Linux %s", v)
		advs := make(map[string][]Update)
		switch v {
		case "1", "2022":
			us, err := options.fetch(options.mirrorURLs[v].Core)
			if err != nil {
				return errors.Wrapf(err, "fetch %s", options.mirrorURLs[v].Core)
			}
			advs[getPackageRepository(options.mirrorURLs[v].Core)] = us
		case "2":
			resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(options.retry)).Get(options.mirrorURLs[v].Extra)
			if err != nil {
				return errors.Wrapf(err, "fetch %s", options.mirrorURLs[v].Extra)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				return errors.Errorf("error response with status code %d", resp.StatusCode)
			}

			var c catalog
			if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
				return errors.Wrap(err, "decode json")
			}

			m := options.mirrorURLs[v]
			for _, t := range c.Topics {
				m.extra = append(m.extra, strings.Replace(options.mirrorURLs[v].Core, "/core/", fmt.Sprintf("/extras/%s/", t.N), 1))
			}
			options.mirrorURLs[v] = m

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
		case "2023":
			us, err := options.fetch(options.mirrorURLs[v].Core)
			if err != nil {
				return errors.Wrapf(err, "fetch %s", options.mirrorURLs[v].Core)
			}
			advs[getPackageRepository(options.mirrorURLs[v].Core)] = us

			us, err = options.fetch(options.mirrorURLs[v].KernelLivePatch)
			if err != nil {
				return errors.Wrapf(err, "fetch %s", options.mirrorURLs[v].KernelLivePatch)
			}
			advs[getPackageRepository(options.mirrorURLs[v].KernelLivePatch)] = us
		default:
			return errors.Errorf("unexpected version. accepts %q, received %q", []string{"1", "2", "2022", "2023"}, v)
		}

		for r, us := range advs {
			log.Printf("[INFO] Fetched Amazon Linux %s %s", v, r)
			bar := progressbar.Default(int64(len(us)))
			for _, u := range us {
				y, err := func() (string, error) {
					switch len(strings.Split(u.ID, "-")) {
					case 3:
						splitted, err := util.Split(u.ID, "-", "-")
						if err != nil {
							return "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALAS(1|2|2022|2023)-yyyy-\\d{3}", u.ID)
						}
						if _, err := time.Parse("2006", splitted[1]); err != nil {
							return "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALAS(1|2|2022|2023)-yyyy-\\d{3}", u.ID)
						}
						return splitted[1], nil
					case 4:
						if !strings.HasPrefix(u.ID, "ALAS2") {
							return "", errors.Errorf("unexpected ID format. expected: %q, actual: %q", "ALAS2.+-.+-yyyy-\\d{3}", u.ID)
						}
						splitted, err := util.Split(u.ID, "-", "-", "-")
						if err != nil {
							return "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALAS2.+-.+-yyyy-\\d{3}", u.ID)
						}
						if _, err := time.Parse("2006", splitted[2]); err != nil {
							return "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "ALAS2.+-.+-yyyy-\\d{3}", u.ID)
						}
						return splitted[2], nil
					default:
						return "", errors.Errorf("unexpected ID format. expected: %q, actual: %q", []string{"ALAS(1|2|2022|2023)-yyyy-\\d{3}", "ALAS2.+-.+-yyyy-\\d{3}"}, u.ID)
					}
				}()
				if err != nil {
					return errors.Wrap(err, "parse id")
				}

				if err := util.Write(filepath.Join(options.dir, v, r, y, fmt.Sprintf("%s.json", u.ID)), u); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(options.dir, v, r, y, fmt.Sprintf("%s.json", u.ID)))
				}

				_ = bar.Add(1)
			}
			_ = bar.Close()
		}
	}

	return nil
}

func (opts options) fetch(mirror string) ([]Update, error) {
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(mirror)
	if err != nil {
		return nil, errors.Wrap(err, "fetch mirror list")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var mirrors []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		mirrors = append(mirrors, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "scanner encounter error")
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
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(repomdURL)
	if err != nil {
		return "", errors.Wrap(err, "fetch repomd")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	var repomd repomd
	if err := xml.NewDecoder(resp.Body).Decode(&repomd); err != nil {
		return "", errors.Wrap(err, "decode repomd.xml")
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
	resp, err := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry)).Get(updateinfoURL)
	if err != nil {
		return nil, errors.Wrap(err, "fetch updateinfo")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, errors.Errorf("error response with status code %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
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
	case strings.Contains(mirror, "/kernel-livepatch/"):
		return "kernel-livepatch"
	default:
		log.Printf("WARN: failed to find repository. mirror: %s", mirror)
		return "unknown"
	}
}
