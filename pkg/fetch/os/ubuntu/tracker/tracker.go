package tracker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu/codename"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const defaultRepoURL = "git://git.launchpad.net/ubuntu-cve-tracker"

type options struct {
	repoURL        string
	dir            string
	retry          int
	compressFormat string
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

type compressFormatOption string

func (c compressFormatOption) apply(opts *options) {
	opts.compressFormat = string(c)
}

func WithCompressFormat(compress string) Option {
	return compressFormatOption(compress)
}

func Fetch(opts ...Option) error {
	options := &options{
		repoURL:        defaultRepoURL,
		dir:            filepath.Join(util.SourceDir(), "ubuntu", "tracker"),
		retry:          3,
		compressFormat: "",
	}

	for _, o := range opts {
		o.apply(options)
	}

	log.Println("[INFO] Fetch Ubuntu Security Tracker")
	cloneDir := filepath.Join(util.SourceDir(), "clone")
	if err := os.RemoveAll(cloneDir); err != nil {
		return errors.Wrapf(err, "remove %s", cloneDir)
	}
	if err := os.MkdirAll(cloneDir, os.ModePerm); err != nil {
		return errors.Wrapf(err, "mkdir %s", cloneDir)
	}

	if err := exec.Command("git", "clone", "--depth", "1", options.repoURL, cloneDir).Run(); err != nil {
		return errors.Wrapf(err, "git clone --depth 1 %s %s", options.repoURL, cloneDir)
	}

	advs := map[string][]Advisory{}
	for release := range codename.CodeToVer {
		advs[release] = []Advisory{}
	}
	for _, target := range []string{"active", "retired", "ignored"} {
		if err := filepath.WalkDir(filepath.Join(cloneDir, target), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			base := filepath.Base(path)
			if !strings.HasPrefix(base, "CVE-") {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return errors.Wrapf(err, "open %s", path)
			}
			defer f.Close()

			as, err := parse(f)
			if err != nil {
				return errors.Wrapf(err, "parse %s", path)
			}
			for release, adv := range as {
				if _, ok := advs[release]; !ok {
					continue
				}
				advs[release] = append(advs[release], adv)
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(cloneDir, target))
		}
	}

	for code, as := range advs {
		v, ok := codename.CodeToVer[code]
		if !ok {
			return errors.Errorf("unexpected codename. accepts %q, received %q", maps.Keys(codename.CodeToVer), code)
		}

		log.Printf("[INFO] Fetched Ubuntu %s Advisory", v)
		dir := filepath.Join(options.dir, v)
		if err := os.RemoveAll(dir); err != nil {
			return errors.Wrapf(err, "remove %s", dir)
		}

		bar := pb.StartNew(len(as))
		for _, adv := range as {
			y := strings.Split(adv.Candidate, "-")[1]
			if _, err := strconv.Atoi(y); err != nil {
				continue
			}

			bs, err := json.Marshal(adv)
			if err != nil {
				return errors.Wrap(err, "marshal json")
			}

			if err := util.Write(util.BuildFilePath(filepath.Join(dir, y, fmt.Sprintf("%s.json", adv.Candidate)), options.compressFormat), bs, options.compressFormat); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(dir, y, adv.Candidate))
			}

			bar.Increment()
		}
		bar.Finish()
	}

	if err := os.RemoveAll(cloneDir); err != nil {
		return errors.Wrapf(err, "remove %s", cloneDir)
	}

	return nil
}

func parse(r io.Reader) (map[string]Advisory, error) {
	var (
		a             advisory
		mode, pkgname string
	)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		t := scanner.Text()
		if strings.HasPrefix(t, "#") || t == "" {
			continue
		}
		switch {
		case strings.HasPrefix(t, "Candidate:"):
			a.Candidate = strings.TrimSpace(strings.TrimPrefix(t, "Candidate:"))
		case strings.HasPrefix(t, "Description:"):
			mode = "Description"
		case strings.HasPrefix(t, "Ubuntu-Description:"):
			mode = "Ubuntu-Description"
		case strings.HasPrefix(t, "Notes:"):
			mode = "Notes"
		case strings.HasPrefix(t, "Mitigation:"):
			mode = "Mitigation"
		case strings.HasPrefix(t, "Priority:"):
			a.Priority = strings.TrimSpace(strings.TrimPrefix(t, "Priority:"))
		case strings.HasPrefix(t, "CVSS:"):
			mode = "CVSS"
		case strings.HasPrefix(t, "Bugs:"):
			mode = "Bugs"
		case strings.HasPrefix(t, "References:"):
			mode = "References"
		case strings.HasPrefix(t, "Assigned-to:"):
			a.AssignedTo = strings.TrimSpace(strings.TrimPrefix(t, "Assigned-to:"))
		case strings.HasPrefix(t, "Discovered-by:"):
			a.DiscoveredBy = strings.TrimSpace(strings.TrimPrefix(t, "Discovered-by:"))
		case strings.HasPrefix(t, "PublicDate:"):
			a.PublicDate = strings.TrimSpace(strings.TrimPrefix(t, "PublicDate:"))
		case strings.HasPrefix(t, "PublicDateAtUSN:"):
			a.PublicDateAtUSN = strings.TrimSpace(strings.TrimPrefix(t, "PublicDateAtUSN:"))
		case strings.HasPrefix(t, "CRD:"):
			a.CRD = strings.TrimSpace(strings.TrimPrefix(t, "CRD:"))
		case strings.HasPrefix(t, "Patches_"):
			mode = "Patches"
			pkgname = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(t, "Patches_")), ":")
		case strings.HasPrefix(t, "Priority_"):
			a.PkgPriorities = append(a.PkgPriorities, strings.TrimSpace(strings.TrimPrefix(t, "Priority_")))
		case strings.HasPrefix(strings.TrimPrefix(t, "-- "), "Tags_"):
			a.PkgTags = append(a.PkgTags, strings.TrimPrefix(strings.TrimPrefix(t, "-- "), "Tags_"))
		case strings.HasPrefix(t, " "):
			if strings.TrimSpace(t) == "" {
				break
			}
			switch mode {
			case "Description":
				a.Description = append(a.Description, strings.TrimSpace(t))
			case "Ubuntu-Description":
				a.UbuntuDescription = append(a.UbuntuDescription, strings.TrimSpace(t))
			case "Notes":
				a.Notes = append(a.Notes, strings.TrimSpace(t))
			case "Mitigation":
				a.Mitigation = append(a.Mitigation, strings.TrimPrefix(t, " "))
			case "CVSS":
				a.CVSS = append(a.CVSS, strings.TrimSpace(t))
			case "Bugs":
				a.Bugs = append(a.Bugs, strings.TrimSpace(t))
			case "References":
				a.References = append(a.References, strings.TrimSpace(t))
			case "Patches":
				if a.PkgPatches == nil {
					a.PkgPatches = map[string][]string{}
				}
				a.PkgPatches[pkgname] = append(a.PkgPatches[pkgname], strings.TrimSpace(t))
			}
		default:
			lhs, rhs, found := strings.Cut(t, ":")
			if !found {
				log.Printf(`[WARN] unexpected package status line. expected: "<release>_<source-package>: <status> (<version/notes>)", actual: "%s"`, t)
				break
			}
			if !strings.Contains(lhs, "_") {
				log.Printf(`[WARN] unexpected package part. expected: "<release>_<source-package>", actual: "%s"`, lhs)
				break
			}
			if strings.TrimSpace(rhs) == "" {
				break
			}
			if status, _, _ := strings.Cut(strings.TrimSpace(rhs), " "); !slices.Contains([]string{"DNE", "needs-triage", "not-affected", "needed", "active", "ignored", "pending", "deferred", "released"}, status) {
				log.Printf(`[WARN] unexpected status part. expected: " <status> (<version/notes>)", actual: "%s"`, rhs)
				break
			}
			a.PkgStatuses = append(a.PkgStatuses, strings.TrimSpace(t))
		}
	}
	return build(a), nil
}

func build(a advisory) map[string]Advisory {
	parseDateFn := func(v string) *time.Time {
		if v == "" || v == "unknown" {
			return nil
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return &t
		}
		if t, err := time.Parse("2006-01-02 15:04:05", v); err == nil {
			return &t
		}
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", v); err == nil {
			return &t
		}
		if t, err := time.Parse("2006-01-02 15:04:05 MST", v); err == nil {
			return &t
		}
		log.Printf(`[WARN] error time.Parse date="%s"`, v)
		return nil
	}

	adv := Advisory{
		Candidate:         a.Candidate,
		Description:       strings.Join(a.Description, " "),
		UbuntuDescription: strings.Join(a.UbuntuDescription, " "),
		Priority:          a.Priority,
		Mitigation:        strings.Join(a.Mitigation, "\n"),
		Bugs:              a.Bugs,
		References:        a.References,
		AssignedTo:        a.AssignedTo,
		DiscoveredBy:      a.DiscoveredBy,
		PublicDate:        parseDateFn(a.PublicDate),
		PublicDateAtUSN:   parseDateFn(a.PublicDateAtUSN),
		CRD:               parseDateFn(a.CRD),
	}

	notes := map[string][]string{}
	var author string
	for _, l := range a.Notes {
		lhs, rhs, found := strings.Cut(l, ">")
		if !found {
			lhs, rhs, found = strings.Cut(l, "|")
			if !found {
				if author == "" {
					log.Printf("[WARN] do not known which author's note it is. candidate: %s. notes: %q", a.Candidate, a.Notes)
					continue
				}
				notes[author] = append(notes[author], l)
				continue
			}
			author = lhs
		} else {
			author = lhs
		}
		notes[author] = append(notes[author], strings.TrimSpace(rhs))
	}
	for author, lines := range notes {
		if adv.Notes == nil {
			adv.Notes = make(map[string]string, len(notes))
		}
		adv.Notes[author] = strings.Join(lines, " ")
	}

	for _, l := range a.CVSS {
		if adv.CVSS == nil {
			adv.CVSS = make(map[string]CVSS, len(a.CVSS))
		}

		src, s, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] unexpected CVSS line. expected: "<name>: <CVSS string>", actual: %q`, l)
			break
		}

		ss := strings.Fields(s)
		if len(ss) != 3 {
			log.Printf(`[WARN] unexpected CVSS part. expected: "<CVSS Vector> [<CVSS Score> <Severity>]", actual: %q`, s)
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimPrefix(ss[1], "["), 64)
		if err != nil {
			log.Printf(`[WARN] failed to parse CVSS Score. score string: %s, err: %s`, strings.TrimPrefix(ss[1], "["), err)
			continue
		}
		adv.CVSS[src] = CVSS{
			Vector:   ss[0],
			Score:    score,
			Severity: strings.TrimSuffix(ss[2], "]"),
		}
	}

	advpkgs := map[string]map[string]Package{}
	for _, l := range a.PkgStatuses {
		lhs, rhs, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] unexpected package status line. expected: "<release>_<source-package>: <status> (<version/notes>)", actual: "%s"`, l)
			continue
		}
		release, pkgname, found := strings.Cut(lhs, "_")
		if !found {
			log.Printf(`[WARN] unexpected package part. expected: "<release>_<source-package>", actual: "%s"`, lhs)
			continue
		}
		if _, ok := advpkgs[release]; !ok {
			advpkgs[release] = map[string]Package{}
		}
		status, note, _ := strings.Cut(strings.TrimSpace(rhs), " ")
		advpkgs[release][pkgname] = Package{
			Name:   pkgname,
			Status: status,
			Note:   strings.Trim(note, "()"),
		}
	}

	for pkgname, ls := range a.PkgPatches {
		patches := []Patch{}
		for _, l := range ls {
			source, text, found := strings.Cut(l, ":")
			if !found {
				log.Printf(`[WARN] unexpected patch line. expected: "<source>: <text>", actual: "%s"`, l)
				continue
			}
			switch source {
			case "break-fix":
				introHash, fixHash, found := strings.Cut(strings.TrimSpace(text), " ")
				if !found {
					log.Printf(`[WARN] unexpected patch break-fix part. expected: " <introduced by hash> <fixed by hash>", actual: "%s"`, text)
					continue
				}
				patches = append(patches,
					Patch{
						Source: "introduced-by",
						Text:   introHash,
					}, Patch{
						Source: "fixed-by",
						Text:   fixHash,
					})
			default:
				patches = append(patches, Patch{
					Source: source,
					Text:   strings.TrimSpace(text),
				})
			}
		}
		for release := range advpkgs {
			p, ok := advpkgs[release][pkgname]
			if !ok {
				continue
			}
			p.Patches = patches
			advpkgs[release][pkgname] = p
		}
	}

	for _, l := range a.PkgTags {
		lhs, rhs, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] unexpected tags line. expected: "<source-package>: <text>", actual: "%s"`, l)
			continue
		}
		tag := strings.TrimSpace(rhs)
		pkgname, release, found := strings.Cut(lhs, "_")
		if !found {
			for r := range advpkgs {
				p, ok := advpkgs[r][pkgname]
				if !ok {
					continue
				}
				p.Tags = append(p.Tags, tag)
				advpkgs[r][pkgname] = p
			}
		} else {
			if _, ok := advpkgs[release]; !ok {
				log.Printf(`[WARN] release for tags not found in package status releases. tags release: "%s", package status releases: %q`, release, maps.Keys(advpkgs))
				continue
			}
			p, ok := advpkgs[release][pkgname]
			if !ok {
				log.Printf(`[WARN] package for tags not found in package status packages. tags package: "%s", package status packages: %q`, pkgname, maps.Keys(advpkgs[release]))
				continue
			}
			p.Tags = append(p.Tags, tag)
			advpkgs[release][pkgname] = p
		}
	}

	for _, l := range a.PkgPriorities {
		lhs, rhs, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] unexpected priority line. expected: "<source-package>: ["negligible", "low", "medium", "high", "critical"]", actual: "%s"`, l)
			continue
		}
		priority := strings.TrimSpace(rhs)
		pkgname, release, found := strings.Cut(lhs, "_")
		if !found {
			for r := range advpkgs {
				p, ok := advpkgs[r][pkgname]
				if !ok {
					continue
				}
				p.Priority = priority
				advpkgs[r][pkgname] = p
			}
		} else {
			if _, ok := advpkgs[release]; !ok {
				log.Printf(`[WARN] release for priority not found in package status releases. priority release: "%s", package status releases: %q`, release, maps.Keys(advpkgs))
				continue
			}
			p, ok := advpkgs[release][pkgname]
			if !ok {
				log.Printf(`[WARN] package for priority not found in package status packages. priority package: "%s", package status packages: %q`, pkgname, maps.Keys(advpkgs[release]))
				continue
			}
			p.Priority = priority
			advpkgs[release][pkgname] = p
		}
	}

	advs := map[string]Advisory{}
	for release, pkgm := range advpkgs {
		adv.Packages = maps.Values(pkgm)
		advs[release] = adv
	}

	return advs
}
