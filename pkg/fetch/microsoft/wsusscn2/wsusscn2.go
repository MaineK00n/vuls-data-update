package wsusscn2

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
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
		dir:         filepath.Join(util.CacheDir(), "fetch", "windows", "wsusscn2"),
		retry:       3,
		concurrency: 2,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Windows WSUSSCN2")
	rootDir, err := options.fetch()
	if err != nil {
		return errors.Wrap(err, "fetch wsusscn2.cab")
	}
	defer os.RemoveAll(filepath.Dir(rootDir))

	f, err := os.Open(filepath.Join(rootDir, "package", "package.xml"))
	if err != nil {
		return errors.Wrapf(err, "open %s", filepath.Join(rootDir, "package", "package.xml"))
	}
	defer f.Close()

	var pkg offlineSyncPackage
	if err := xml.NewDecoder(f).Decode(&pkg); err != nil {
		return errors.Wrap(err, "decode package.xml")
	}

	rIDtoUID := make(map[string]string)
	for _, u := range pkg.Updates.Update {
		if u.IsBundle != "true" || u.IsSoftware == "false" {
			continue
		}
		rIDtoUID[u.RevisionID] = u.UpdateID
	}

	f, err = os.Open(filepath.Join(rootDir, "index.xml"))
	if err != nil {
		return errors.Wrap(err, "open wsusscn2/index.xml")
	}
	defer f.Close()

	var cabIndex index
	if err := xml.NewDecoder(f).Decode(&cabIndex); err != nil {
		return errors.Wrap(err, "decode xml")
	}

	cabs := []cab{}
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

	log.Printf("[INFO] Fetched %d Updates", len(rIDtoUID))
	bar := pb.StartNew(len(rIDtoUID))
	for _, u := range pkg.Updates.Update {
		if u.IsBundle != "true" || u.IsSoftware == "false" {
			continue
		}

		if err := util.Write(filepath.Join(options.dir, "u", fmt.Sprintf("%s.json", u.UpdateID)), u); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "u", fmt.Sprintf("%s.json", u.UpdateID)))
		}

		ridint, err := strconv.ParseUint(u.RevisionID, 10, 32)
		if err != nil {
			return errors.Wrap(err, "parse uint")
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

		x, l, err := func() (X, L, error) {
			f, err := os.Open(filepath.Join(rootDir, pname, "x", u.RevisionID))
			if err != nil {
				return X{}, L{}, errors.Wrapf(err, "open wsusscn2/%s/x/%s", pname, u.RevisionID)
			}
			defer f.Close()

			var x X
			if err := xml.NewDecoder(f).Decode(&x); err != nil {
				return X{}, L{}, errors.Wrap(err, "decode xml")
			}

			f, err = os.Open(filepath.Join(rootDir, pname, "l", u.DefaultLanguage, u.RevisionID))
			if err != nil {
				return X{}, L{}, errors.Wrapf(err, "open wsusscn2/%s/l/%s/%s", pname, u.DefaultLanguage, u.RevisionID)
			}
			defer f.Close()

			var l L
			if err := xml.NewDecoder(f).Decode(&l); err != nil {
				return X{}, L{}, errors.Wrap(err, "decode xml")
			}

			return x, l, nil
		}()
		if err != nil {
			return errors.WithStack(err)
		}

		if err := util.Write(filepath.Join(options.dir, "x", fmt.Sprintf("%s.json", u.RevisionID)), x); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "x", fmt.Sprintf("%s.json", u.RevisionID)))
		}

		if err := util.Write(filepath.Join(options.dir, "l", fmt.Sprintf("%s.json", u.RevisionID)), l); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "l", fmt.Sprintf("%s.json", u.RevisionID)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (opts options) fetch() (string, error) {
	dir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return "", errors.Wrap(err, "make directory")
	}

	rc := retryablehttp.NewClient()
	rc.RetryMax = opts.retry
	rc.Logger = nil

	resp, err := rc.Get(opts.dataURL)
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

	log.Printf("[INFO] extract %s", filepath.Join(tmpDir, "wsusscn2.cab"))
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

	log.Printf("[INFO] extract %s", filepath.Join(tmpDir, "wsusscn2", "package.cab"))
	if err := exec.Command(binPath, "-d", filepath.Join(tmpDir, "wsusscn2", "package"), filepath.Join(tmpDir, "wsusscn2", "package.cab")).Run(); err != nil {
		return errors.Wrap(err, "run cabextract wsusscn2/package.cab")
	}
	if err := os.Remove(filepath.Join(tmpDir, "wsusscn2", "package.cab")); err != nil {
		return errors.Wrap(err, "remove wsusscn2/package.cab")
	}

	log.Printf("[INFO] extract %s - %s", filepath.Join(tmpDir, "wsusscn2", "package2.cab"), filepath.Join(tmpDir, "wsusscn2", fmt.Sprintf("package%d.cab", len(cabIndex.CABLIST.CAB))))
	bar := pb.StartNew(len(cabIndex.CABLIST.CAB) - 1)
	eg, _ := errgroup.WithContext(context.Background())
	eg.SetLimit(opts.concurrency)
	for _, c := range cabIndex.CABLIST.CAB {
		c := c
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
				if filepath.Base(dir.Name()) == "x" || filepath.Base(dir.Name()) == "l" {
					continue
				}
				if err := os.RemoveAll(filepath.Join(tmpDir, "wsusscn2", strings.TrimSuffix(c.NAME, ".cab"), dir.Name())); err != nil {
					return errors.Wrapf(err, "remove wsusscn2/%s/%s", strings.TrimSuffix(c.NAME, ".cab"), dir.Name())
				}
			}

			bar.Increment()

			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return errors.Wrapf(err, "extract %s", filepath.Join(tmpDir, "wsusscn2", "package\\d{1,2}.cab"))
	}
	bar.Finish()

	return nil
}
