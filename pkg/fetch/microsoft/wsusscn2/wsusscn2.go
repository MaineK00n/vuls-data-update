package wsusscn2

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilhttp "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/http"
)

const dataURL = "http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab"

type options struct {
	dataURL     string
	dir         string
	retry       int
	concurrency int
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

type concurrencyOption int

func (c concurrencyOption) apply(opts *options) {
	opts.concurrency = int(c)
}

func WithConcurrency(concurrency int) Option {
	return concurrencyOption(concurrency)
}

func Fetch(opts ...Option) error {
	options := &options{
		dataURL:     dataURL,
		dir:         filepath.Join(util.CacheDir(), "fetch", "microsoft", "wsusscn2"),
		retry:       3,
		concurrency: 2,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Windows WSUSSCN2")
	rootDir, err := options.fetch()
	if err != nil {
		return errors.Wrap(err, "fetch wsusscn2.cab")
	}
	defer os.RemoveAll(filepath.Dir(rootDir))

	if err := options.save(rootDir); err != nil {
		return errors.Wrap(err, "save wsusscn2")
	}

	return nil
}

func (opts options) fetch() (string, error) {
	dir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return "", errors.Wrap(err, "make directory")
	}

	c := utilhttp.NewClient(utilhttp.WithClientRetryMax(opts.retry))
	resp, err := c.Get(opts.dataURL)
	if err != nil {
		return "", errors.Wrapf(err, "http get, url: %s", opts.dataURL)
	}
	defer resp.Body.Close()

	f, err := os.Create(filepath.Join(dir, "wsusscn2.cab"))
	if err != nil {
		return "", errors.Wrapf(err, "create %s", filepath.Join(dir, "wsusscn2.cab"))
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", errors.Wrap(err, "copy to wsusscn2.cab from response body")
	}

	if err := opts.extract(dir); err != nil {
		return "", errors.Wrap(err, "extract wsusscn2.cab")
	}

	return filepath.Join(dir, "wsusscn2"), nil
}

func (opts options) extract(tmpDir string) error {
	binPath, err := exec.LookPath("cabextract")
	if err != nil {
		return errors.Wrap(err, "look cabextract path")
	}

	slog.Info("extract", slog.String("path", filepath.Join(tmpDir, "wsusscn2.cab")))
	if err := exec.Command(binPath, "-d", filepath.Join(tmpDir, "wsusscn2"), filepath.Join(tmpDir, "wsusscn2.cab")).Run(); err != nil {
		return errors.Wrap(err, "run cabextract wsusscn2.cab")
	}
	if err := os.Remove(filepath.Join(tmpDir, "wsusscn2.cab")); err != nil {
		return errors.Wrap(err, "remove wsusscn2.cab")
	}

	f, err := os.Open(filepath.Join(tmpDir, "wsusscn2", "index.xml"))
	if err != nil {
		return errors.Wrap(err, "open wsusscn2/index.xml")
	}
	defer f.Close()

	var cabIndex index
	if err := xml.NewDecoder(f).Decode(&cabIndex); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	slog.Info("extract", slog.String("path", filepath.Join(tmpDir, "wsusscn2", "package.cab")))
	if err := exec.Command(binPath, "-d", filepath.Join(tmpDir, "wsusscn2", "package"), filepath.Join(tmpDir, "wsusscn2", "package.cab")).Run(); err != nil {
		return errors.Wrap(err, "run cabextract wsusscn2/package.cab")
	}
	if err := os.Remove(filepath.Join(tmpDir, "wsusscn2", "package.cab")); err != nil {
		return errors.Wrap(err, "remove wsusscn2/package.cab")
	}

	slog.Info("extract", slog.String("from", filepath.Join(tmpDir, "wsusscn2", "package2.cab")), slog.String("to", filepath.Join(tmpDir, "wsusscn2", fmt.Sprintf("package%d.cab", len(cabIndex.CABLIST.CAB)))))
	eg, _ := errgroup.WithContext(context.TODO())
	eg.SetLimit(opts.concurrency)
	for _, c := range cabIndex.CABLIST.CAB {
		eg.Go(func() error {
			if c.NAME == "package.cab" {
				return nil
			}
			if err := exec.Command(binPath, "-d", filepath.Join(tmpDir, "wsusscn2", strings.TrimSuffix(c.NAME, ".cab")), filepath.Join(tmpDir, "wsusscn2", c.NAME)).Run(); err != nil {
				return errors.Wrapf(err, "cabextract wsusscn2/%s", c.NAME)
			}
			if err := os.Remove(filepath.Join(tmpDir, "wsusscn2", c.NAME)); err != nil {
				return errors.Wrapf(err, "remove wsusscn2/%s", c.NAME)
			}

			dirs, err := os.ReadDir(filepath.Join(tmpDir, "wsusscn2", strings.TrimSuffix(c.NAME, ".cab")))
			if err != nil {
				return errors.Wrapf(err, "read wsusscn2/%s", strings.TrimSuffix(c.NAME, ".cab"))
			}
			for _, dir := range dirs {
				switch filepath.Base(dir.Name()) {
				case "c", "x", "l":
				default:
					if err := os.RemoveAll(filepath.Join(tmpDir, "wsusscn2", strings.TrimSuffix(c.NAME, ".cab"), dir.Name())); err != nil {
						return errors.Wrapf(err, "remove wsusscn2/%s/%s", strings.TrimSuffix(c.NAME, ".cab"), dir.Name())
					}
				}
			}

			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return errors.Wrapf(err, "extract %s", filepath.Join(tmpDir, "wsusscn2", "package\\d{1,2}.cab"))
	}

	return nil
}

func (opts options) save(root string) error {
	slog.Info("save wsusscn2 update, core, extended, localized data")

	f, err := os.Open(filepath.Join(root, "package", "package.xml"))
	if err != nil {
		return errors.Wrapf(err, "open %s", filepath.Join(root, "package", "package.xml"))
	}
	defer f.Close()

	var pkg offlineSyncPackage
	if err := xml.NewDecoder(f).Decode(&pkg); err != nil {
		return errors.Wrap(err, "decode package.xml")
	}

	f, err = os.Open(filepath.Join(root, "index.xml"))
	if err != nil {
		return errors.Wrap(err, "open wsusscn2/index.xml")
	}
	defer f.Close()

	var cabIndex index
	if err := xml.NewDecoder(f).Decode(&cabIndex); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	cabs := make([]cab, 0, len(cabIndex.CABLIST.CAB))
	for _, c := range cabIndex.CABLIST.CAB {
		if c.RANGESTART == "" {
			continue
		}
		cabs = append(cabs, c)
	}
	slices.SortFunc(cabs, func(a, b cab) int {
		ai, aerr := strconv.Atoi(a.RANGESTART)
		bi, berr := strconv.Atoi(b.RANGESTART)
		if aerr != nil && berr != nil {
			return 0
		}
		if aerr != nil || ai > bi {
			return -1
		}
		if berr != nil || ai < bi {
			return +1
		}
		return 0
	})

	eg, _ := errgroup.WithContext(context.TODO())
	eg.SetLimit(opts.concurrency)
	for _, u := range pkg.Updates.Update {
		eg.Go(func() error {
			ridint, err := strconv.ParseUint(u.RevisionID, 10, 32)
			if err != nil {
				return errors.Wrap(err, "parse uint")
			}

			if err := util.Write(filepath.Join(opts.dir, "u", fmt.Sprintf("%s.json", u.RevisionID)), u); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "u", fmt.Sprintf("%s.json", u.RevisionID)))
			}

			pname, err := func() (string, error) {
				for _, c := range cabs {
					cabint, err := strconv.ParseUint(c.RANGESTART, 10, 32)
					if err != nil {
						return "", errors.Wrap(err, "parse uint")
					}

					if ridint < cabint {
						continue
					}

					return strings.TrimSuffix(c.NAME, ".cab"), nil
				}
				return "", errors.Errorf("not found cab directory for revision id %s", u.RevisionID)
			}()
			if err != nil {
				return errors.WithStack(err)
			}

			c, err := func() (*C, error) {
				bs, err := os.ReadFile(filepath.Join(root, pname, "c", u.RevisionID))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil, nil
					}
					return nil, errors.Wrapf(err, "read %s", filepath.Join(root, pname, "c", u.RevisionID))
				}

				var c C
				if err := xml.Unmarshal(fmt.Appendf(nil, "<CoreProperties>%s</CoreProperties>", string(bs)), &c); err != nil {
					return nil, errors.Wrapf(err, "unmarshal %s", filepath.Join(root, pname, "c", u.RevisionID))
				}

				return &c, nil
			}()
			if err != nil {
				return errors.WithStack(err)
			}
			if c != nil {
				if err := util.Write(filepath.Join(opts.dir, "c", fmt.Sprintf("%s.json", u.RevisionID)), *c); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "c", fmt.Sprintf("%s.json", u.RevisionID)))
				}
			}

			x, err := func() (*X, error) {
				f, err := os.Open(filepath.Join(root, pname, "x", u.RevisionID))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil, nil
					}
					return nil, errors.Wrapf(err, "open %s", filepath.Join(root, pname, "x", u.RevisionID))
				}
				defer f.Close()

				var x X
				if err := xml.NewDecoder(f).Decode(&x); err != nil {
					return nil, errors.Wrapf(err, "decode %s", filepath.Join(root, pname, "x", u.RevisionID))
				}

				return &x, nil
			}()
			if err != nil {
				return errors.WithStack(err)
			}
			if x != nil {
				if err := util.Write(filepath.Join(opts.dir, "x", fmt.Sprintf("%s.json", u.RevisionID)), *x); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "x", fmt.Sprintf("%s.json", u.RevisionID)))
				}
			}

			l, err := func() (*L, error) {
				f, err := os.Open(filepath.Join(root, pname, "l", u.DefaultLanguage, u.RevisionID))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil, nil
					}
					return nil, errors.Wrapf(err, "open %s", filepath.Join(root, pname, "l", u.DefaultLanguage, u.RevisionID))
				}
				defer f.Close()

				var l L
				if err := xml.NewDecoder(f).Decode(&l); err != nil {
					return nil, errors.Wrapf(err, "decode %s", filepath.Join(root, pname, "l", u.DefaultLanguage, u.RevisionID))
				}

				return &l, nil
			}()
			if err != nil {
				return errors.WithStack(err)
			}
			if l != nil {
				if err := util.Write(filepath.Join(opts.dir, "l", fmt.Sprintf("%s.json", u.RevisionID)), *l); err != nil {
					return errors.Wrapf(err, "write %s", filepath.Join(opts.dir, "l", fmt.Sprintf("%s.json", u.RevisionID)))
				}
			}

			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "save wsusscn2 update, core, extended, localized data")
	}

	return nil
}
