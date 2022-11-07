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
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
	"golang.org/x/net/html/charset"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type options struct {
	mirrorURLs     map[string]MirrorURL
	dir            string
	retry          int
	compressFormat string
}

type MirrorURL struct {
	Mirror    string
	Releasemd string
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		mirrorURLs: map[string]MirrorURL{
			"1": {Mirror: "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list"},
			"2": {Mirror: "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list"},
			"2022": {
				Mirror:    "https://al2022-repos-us-east-1-9761ab97.s3.dualstack.us-east-1.amazonaws.com/core/mirrors/%s/x86_64/mirror.list",
				Releasemd: "https://al2022-repos-us-west-2-9761ab97.s3.dualstack.us-west-2.amazonaws.com/core/releasemd.xml",
			},
		},
		dir:            filepath.Join(util.SourceDir(), "amazon"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	for v := range options.mirrorURLs {
		log.Printf("[INFO] Fetch Amazon Linux %s", v)
		switch v {
		case "1", "2":
		case "2022":
			u, err := options.fetchAmazonLinux2022Mirror(options.mirrorURLs[v])
			if err != nil {
				return errors.Wrap(err, "fetch amazon linux 2022 mirror")
			}
			options.mirrorURLs[v] = MirrorURL{Mirror: u}
		default:
			return errors.Errorf("unexpected version. accepts %q, received %q", []string{"1", "2", "2022"}, v)
		}

		us, err := options.fetch(v)
		if err != nil {
			return errors.Wrapf(err, "fetch amazon linux %s updateinfo", v)
		}

		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}
		bar := pb.StartNew(len(us))
		for _, u := range us {
			y := strings.Split(u.ID, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				continue
			}

			bs, err := json.Marshal(u)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(dir, y, fmt.Sprintf("%s.json", u.ID)), options.compressFormat), bs, options.compressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(dir, y, u.ID))
			}

			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (opts options) fetch(version string) ([]Advisory, error) {
	bs, err := util.FetchURL(opts.mirrorURLs[version].Mirror, opts.retry)
	if err != nil {
		return nil, errors.Wrap(err, "fetch mirror list")
	}

	var mirrors []string
	scanner := bufio.NewScanner(bytes.NewReader(bs))
	for scanner.Scan() {
		mirrors = append(mirrors, scanner.Text())
	}

	var advs []Advisory
	for _, mirror := range mirrors {
		u, err := url.JoinPath(mirror, "/repodata/repomd.xml")
		if err != nil {
			return nil, errors.Wrap(err, "join url path")
		}
		uinfoPath, err := opts.fetchUpdateInfoPath(u)
		if err != nil {
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

		parseDateFn := func(v string) *time.Time {
			if v == "" {
				return nil
			}
			if t, err := time.Parse("2006-01-02 15:04", v); err == nil {
				return &t
			}
			log.Printf(`[WARN] error time.Parse date="%s"`, v)
			return nil
		}
		for _, u := range us {
			advs = append(advs, Advisory{
				ID:          u.ID,
				Type:        u.Type,
				Author:      u.Author,
				From:        u.From,
				Status:      u.Status,
				Version:     u.Version,
				Title:       u.Title,
				Description: u.Description,
				Severity:    u.Severity,
				Pkglist: Pkglist{
					Short:      u.Pkglist.Short,
					Name:       u.Pkglist.Name,
					Repository: "",
					Package:    u.Pkglist.Package,
				},
				References: u.References,
				Issued:     parseDateFn(u.Issued.Date),
				Updated:    parseDateFn(u.Updated.Date),
			})
		}
	}
	return advs, nil
}

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
		return "", errors.New("no updateinfo field")
	}
	return updateInfoPath, nil
}

func (opts options) fetchUpdateInfo(updateinfoURL string) ([]update, error) {
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

func (opts options) fetchAmazonLinux2022Mirror(mirror MirrorURL) (string, error) {
	bs, err := util.FetchURL(mirror.Releasemd, opts.retry)
	if err != nil {
		return "", errors.Wrap(err, "fetch releasemd")
	}

	var r releasemd
	decoder := xml.NewDecoder(bytes.NewReader(bs))
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&r); err != nil {
		return "", errors.Wrap(err, "decode releasemd")
	}

	var vs []string
	for _, r := range r.Releases.Release {
		vs = append(vs, r.Version)
	}
	if len(vs) == 0 {
		return "", errors.Errorf("version list for amazon linux 2022 is empty")
	}

	slices.Sort(vs)
	return fmt.Sprintf(mirror.Mirror, vs[len(vs)-1]), nil
}
