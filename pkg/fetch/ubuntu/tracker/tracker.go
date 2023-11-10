package tracker

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

const defaultRepoURL = "git://git.launchpad.net/ubuntu-cve-tracker"

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
		dir:     filepath.Join(util.CacheDir(), "ubuntu", "tracker"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Ubuntu Security Tracker")
	cloneDir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return errors.Wrapf(err, "mkdir %s", cloneDir)
	}
	defer os.RemoveAll(cloneDir)

	if err := exec.Command("git", "clone", "--depth", "1", options.repoURL, cloneDir).Run(); err != nil {
		return errors.Wrapf(err, "git clone --depth 1 %s %s", options.repoURL, cloneDir)
	}

	advs := []Advisory{}
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

			a, err := parse(f)
			if err != nil {
				return errors.Wrapf(err, "parse %s", path)
			}
			advs = append(advs, a)

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(cloneDir, target))
		}
	}

	bar := pb.StartNew(len(advs))
	for _, a := range advs {
		splitted, err := util.Split(a.Candidate, "-", "-")
		if err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.Candidate)
			continue
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			log.Printf("[WARN] unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.Candidate)
			continue
		}

		if err := util.Write(filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.Candidate)), a); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", a.Candidate)))
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func parse(r io.Reader) (Advisory, error) {
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
				log.Printf(`[WARN] %s: unexpected package status line. expected: "<release>_<source-package>: <status> (<version/notes>)", actual: "%s"`, a.Candidate, t)
				break
			}
			if !strings.Contains(lhs, "_") {
				log.Printf(`[WARN] %s: unexpected package part. expected: "<release>_<source-package>", actual: "%s"`, a.Candidate, lhs)
				break
			}
			if strings.TrimSpace(rhs) == "" {
				break
			}
			if status, _, _ := strings.Cut(strings.TrimSpace(rhs), " "); !slices.Contains([]string{"DNE", "needs-triage", "not-affected", "needed", "active", "ignored", "pending", "deferred", "released"}, status) {
				log.Printf(`[WARN] %s: unexpected status part. expected: " <status> (<version/notes>)", actual: "%s"`, a.Candidate, rhs)
				break
			}
			a.PkgStatuses = append(a.PkgStatuses, strings.TrimSpace(t))
		}
	}
	if err := scanner.Err(); err != nil {
		return Advisory{}, errors.Wrap(err, "scanner encounter error")
	}
	return build(a), nil
}

func build(a advisory) Advisory {
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
		PublicDate:        a.PublicDate,
		PublicDateAtUSN:   a.PublicDateAtUSN,
		CRD:               a.CRD,
	}

	notes := map[string][]string{}
	var author string
	for _, l := range a.Notes {
		lhs, rhs, found := strings.Cut(l, ">")
		if !found {
			lhs, rhs, found = strings.Cut(l, "|")
			if !found {
				if author == "" {
					log.Printf("[WARN] %s: do not known which author's note it is. notes: %q", a.Candidate, a.Notes)
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
			adv.CVSS = make(map[string]string, len(a.CVSS))
		}

		src, s, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] %s: unexpected CVSS line. expected: "<name>: <CVSS string>", actual: %q`, a.Candidate, l)
			break
		}
		adv.CVSS[src] = s
	}

	adv.Packages = map[string]map[string]Package{}
	for _, l := range a.PkgStatuses {
		lhs, rhs, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] %s: unexpected package status line. expected: "<release>_<source-package>: <status> (<version/notes>)", actual: "%s"`, a.Candidate, l)
			continue
		}
		release, pkgname, found := strings.Cut(lhs, "_")
		if !found {
			log.Printf(`[WARN] %s: unexpected package part. expected: "<release>_<source-package>", actual: "%s"`, a.Candidate, lhs)
			continue
		}
		if _, ok := adv.Packages[release]; !ok {
			adv.Packages[release] = map[string]Package{}
		}
		status, note, _ := strings.Cut(strings.TrimSpace(rhs), " ")
		adv.Packages[release][pkgname] = Package{
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
				log.Printf(`[WARN] %s: unexpected patch line. expected: "<source>: <text>", actual: "%s"`, a.Candidate, l)
				continue
			}
			switch source {
			case "break-fix":
				introHash, fixHash, found := strings.Cut(strings.TrimSpace(text), " ")
				if !found {
					log.Printf(`[WARN] %s: unexpected patch break-fix part. expected: " <introduced by hash> <fixed by hash>", actual: "%s"`, a.Candidate, text)
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
		for release := range adv.Packages {
			p, ok := adv.Packages[release][pkgname]
			if !ok {
				continue
			}
			p.Patches = patches
			adv.Packages[release][pkgname] = p
		}
	}

	for _, l := range a.PkgTags {
		lhs, rhs, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] %s: unexpected tags line. expected: "<source-package>: <text>", actual: "%s"`, a.Candidate, l)
			continue
		}
		tag := strings.TrimSpace(rhs)
		pkgname, release, found := strings.Cut(lhs, "_")
		if !found {
			for r := range adv.Packages {
				p, ok := adv.Packages[r][pkgname]
				if !ok {
					continue
				}
				p.Tags = append(p.Tags, tag)
				adv.Packages[r][pkgname] = p
			}
		} else {
			if _, ok := adv.Packages[release]; !ok {
				log.Printf(`[WARN] %s: release for tags not found in package status releases. tags release: "%s", package status releases: %q`, a.Candidate, release, maps.Keys(adv.Packages))
				continue
			}
			p, ok := adv.Packages[release][pkgname]
			if !ok {
				log.Printf(`[WARN] %s: package for tags not found in package status packages. tags package: "%s", package status packages: %q`, a.Candidate, pkgname, maps.Keys(adv.Packages[release]))
				continue
			}
			p.Tags = append(p.Tags, tag)
			adv.Packages[release][pkgname] = p
		}
	}

	for _, l := range a.PkgPriorities {
		lhs, rhs, found := strings.Cut(l, ":")
		if !found {
			log.Printf(`[WARN] %s: unexpected priority line. expected: "<source-package>: ["negligible", "low", "medium", "high", "critical"]", actual: "%s"`, a.Candidate, l)
			continue
		}
		priority := strings.TrimSpace(rhs)
		pkgname, release, found := strings.Cut(lhs, "_")
		if !found {
			for r := range adv.Packages {
				p, ok := adv.Packages[r][pkgname]
				if !ok {
					continue
				}
				p.Priority = priority
				adv.Packages[r][pkgname] = p
			}
		} else {
			if _, ok := adv.Packages[release]; !ok {
				log.Printf(`[WARN] %s: release for priority not found in package status releases. priority release: "%s", package status releases: %q`, a.Candidate, release, maps.Keys(adv.Packages))
				continue
			}
			p, ok := adv.Packages[release][pkgname]
			if !ok {
				log.Printf(`[WARN] %s: package for priority not found in package status packages. priority package: "%s", package status packages: %q`, a.Candidate, pkgname, maps.Keys(adv.Packages[release]))
				continue
			}
			p.Priority = priority
			adv.Packages[release][pkgname] = p
		}
	}

	return adv
}
