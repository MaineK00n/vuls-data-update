package gentoo

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const defaultRepoURL = "https://anongit.gentoo.org/git/data/glsa.git"

type options struct {
	repoURL string
	dir     string
	retry   int
}

type Option interface {
	apply(*options)
}

type repoURLOption string

func (u repoURLOption) apply(opts *options) {
	opts.repoURL = string(u)
}

func WithRepoURL(repoURL string) Option {
	return repoURLOption(repoURL)
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
		repoURL: defaultRepoURL,
		dir:     filepath.Join(util.CacheDir(), "gentoo"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Fetch Gentoo Linux")

	cloneDir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return errors.Wrapf(err, "mkdir %s", cloneDir)
	}
	defer os.RemoveAll(cloneDir)

	if err := exec.Command("git", "clone", "--depth", "1", options.repoURL, cloneDir).Run(); err != nil {
		return errors.Wrapf(err, "git clone --depth 1 %s %s", options.repoURL, cloneDir)
	}

	var as []GLSA
	if err := filepath.WalkDir(cloneDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.WithStack(err)
		}

		if d.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".xml") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.Wrapf(err, "open %s", path)
		}
		defer f.Close()

		var a GLSA
		if err := xml.NewDecoder(f).Decode(&a); err != nil {
			return errors.Wrap(err, "decode xml")
		}

		as = append(as, a)

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", cloneDir)
	}

	bar := pb.StartNew(len(as))
	for _, a := range as {
		splitted, err := util.Split(a.ID, "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "yyymm-\\d{2,}", a.ID)
			continue
		}
		if _, err := time.Parse("200601", splitted[0]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "yyyymm-\\d{2,}", a.ID)
			continue
		}

		if err := util.Write(filepath.Join(options.dir, splitted[0][:4], fmt.Sprintf("GLSA-%s.json", a.ID)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[0][:4], fmt.Sprintf("GLSA-%s.json", a.ID)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
