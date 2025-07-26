package tracker

import (
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

	"github.com/pkg/errors"

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
		dir:     filepath.Join(util.CacheDir(), "fetch", "ubuntu", "ubuntu-cve-tracker"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Println("[INFO] Fetch Ubuntu CVE Tracker")
	cloneDir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return errors.Wrapf(err, "mkdir %s", cloneDir)
	}
	defer os.RemoveAll(cloneDir)

	if err := exec.Command("git", "clone", "--depth", "1", options.repoURL, cloneDir).Run(); err != nil {
		return errors.Wrapf(err, "git clone --depth 1 %s %s", options.repoURL, cloneDir)
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

			a, err := parse(f)
			if err != nil {
				return errors.Wrapf(err, "parse %s", path)
			}

			splitted, err := util.Split(a.Candidate, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.Candidate)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", a.Candidate)
			}

			if err := util.Write(filepath.Join(options.dir, target, splitted[1], fmt.Sprintf("%s.json", a.Candidate)), a); err != nil {
				return errors.Wrapf(err, "write %s", filepath.Join(options.dir, target, splitted[1], fmt.Sprintf("%s.json", a.Candidate)))
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(cloneDir, target))
		}
	}

	return nil
}

func parse(r io.Reader) (Advisory, error) {
	var a Advisory

	bs, err := io.ReadAll(r)
	if err != nil {
		return Advisory{}, errors.Wrap(err, "read all")
	}

	lines := strings.Split(string(bs), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "Candidate:"):
			a.Candidate = strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
		case strings.HasPrefix(line, "Description:"):
			var description []string
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					description = append(description, strings.TrimSpace(lines[i]))
				}
			}
			a.Description = strings.Join(description, " ")
		case strings.HasPrefix(line, "Ubuntu-Description:"):
			var description []string
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					description = append(description, strings.TrimSpace(lines[i]))
				}
			}
			a.UbuntuDescription = strings.Join(description, " ")
		case strings.HasPrefix(line, "Notes:"):
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				note := []string{strings.TrimSpace(lines[i])}
				for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], "  ") || lines[i+1] == "") {
					i++
					if strings.TrimSpace(lines[i]) != "" {
						note = append(note, strings.TrimSpace(lines[i]))
					}
				}
				a.Notes = append(a.Notes, strings.Join(note, " "))
			}
		case strings.HasPrefix(line, "Mitigation:"):
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				mitigation := []string{strings.TrimSpace(lines[i])}
				for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], "  ") || lines[i+1] == "") {
					i++
					if strings.TrimSpace(lines[i]) != "" {
						mitigation = append(mitigation, strings.TrimSpace(lines[i]))
					}
				}
				a.Mitigation = append(a.Mitigation, strings.Join(mitigation, " "))
			}
		case strings.HasPrefix(line, "Priority:"):
			a.Priority = &Priority{Priority: strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))}
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					a.Priority.Reasons = append(a.Priority.Reasons, strings.TrimSpace(lines[i]))
				}
			}
		case strings.HasPrefix(line, "CVSS:"):
			cvss := make(map[string][]string)
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					lhs, rhs, ok := strings.Cut(strings.TrimSpace(lines[i]), ":")
					if !ok {
						return Advisory{}, errors.Errorf("unexpected CVSS line. expected: %q, actual: %q", "<name>: <CVSS string>", lines[i])
					}
					cvss[lhs] = append(cvss[lhs], strings.TrimSpace(rhs))
				}
			}
			if len(cvss) > 0 {
				a.CVSS = cvss
			}
		case strings.HasPrefix(line, "Bugs:"):
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					a.Bugs = append(a.Bugs, strings.TrimSpace(lines[i]))
				}
			}
		case strings.HasPrefix(line, "References:"):
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					a.References = append(a.References, strings.TrimSpace(lines[i]))
				}
			}
		case strings.HasPrefix(line, "Tags:"):
			a.Tags = strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "Tags:")))
		case strings.HasPrefix(line, "Assigned-to:"):
			assignedTo := []string{strings.TrimSpace(strings.TrimPrefix(line, "Assigned-to:"))}
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					assignedTo = append(assignedTo, strings.TrimSpace(lines[i]))
				}
			}
			a.AssignedTo = strings.Join(assignedTo, " ")
		case strings.HasPrefix(line, "Discovered-by:"):
			discoveredBy := []string{strings.TrimSpace(strings.TrimPrefix(line, "Discovered-by:"))}
			for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
				i++
				if strings.TrimSpace(lines[i]) != "" {
					discoveredBy = append(discoveredBy, strings.TrimSpace(lines[i]))
				}
			}
			a.DiscoveredBy = strings.Join(discoveredBy, " ")
		case strings.HasPrefix(line, "PublicDate:"):
			a.PublicDate = strings.TrimSpace(strings.TrimPrefix(line, "PublicDate:"))
		case strings.HasPrefix(line, "PublicDateAtUSN:"):
			a.PublicDateAtUSN = strings.TrimSpace(strings.TrimPrefix(line, "PublicDateAtUSN:"))
		case strings.HasPrefix(line, "CRD:"):
			a.CRD = strings.TrimSpace(strings.TrimPrefix(line, "CRD:"))
		default:
			lhs, rhs, ok := strings.Cut(line, "_")
			if !ok {
				log.Printf("[WARN] unexpected line format in %s. expected: %q, actual: %q", a.Candidate, "<prefix>_<package>: <text>", line)
				break
			}

			switch lhs {
			case "Patches":
				lhs, _, ok := strings.Cut(rhs, ":")
				if !ok {
					return Advisory{}, errors.Errorf("unexpected patch format. expected: %q, actual: %q", "Patches_<package>:", line)
				}

				var patches []Patch
				for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
					i++

					if strings.TrimSpace(lines[i]) != "" {
						lhs, rhs, ok := strings.Cut(strings.TrimSpace(lines[i]), ":")
						if !ok {
							return Advisory{}, errors.Errorf("unexpected patch format. expected: %q, actual: %q", "<source>: <text>", lines[i])
						}
						patches = append(patches, Patch{
							Source: lhs,
							Text:   strings.TrimSpace(rhs),
						})
					}
				}

				if len(patches) > 0 {
					if a.Packages == nil {
						a.Packages = make(map[string]Package)
					}
					base, ok := a.Packages[lhs]
					if ok {
						if len(base.Patches) > 0 {
							return Advisory{}, errors.Errorf("duplicate patches for package %s", lhs)
						}
					}
					base.Patches = patches
					a.Packages[lhs] = base
				}
			case "Priority":
				lhs, priority, ok := strings.Cut(rhs, ":")
				if !ok {
					return Advisory{}, errors.Errorf("unexpected priority format. expected: %q, actual: %q", "Priority_<package>(_<release>): <priority>", line)
				}
				p := Priority{Priority: strings.TrimSpace(priority)}
				for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || lines[i+1] == "") {
					i++
					if strings.TrimSpace(lines[i]) != "" {
						p.Reasons = append(p.Reasons, strings.TrimSpace(lines[i]))
					}
				}

				lhs, rhs, ok := strings.Cut(lhs, "_")
				if ok {
					if a.Packages == nil {
						a.Packages = make(map[string]Package)
					}
					base := a.Packages[lhs]
					if base.Releases == nil {
						base.Releases = make(map[string]Release)
					}
					release, ok := base.Releases[rhs]
					if ok {
						if release.Priority != nil {
							return Advisory{}, errors.Errorf("duplicate priority for release %s package %s", rhs, lhs)
						}
					}
					release.Priority = &p
					base.Releases[rhs] = release
					a.Packages[lhs] = base
				} else {
					if a.Packages == nil {
						a.Packages = make(map[string]Package)
					}
					base, ok := a.Packages[lhs]
					if ok {
						if base.Priority != nil {
							return Advisory{}, errors.Errorf("duplicate priority for package %s", lhs)
						}
					}
					base.Priority = &p
					a.Packages[lhs] = base
				}
			case "Tags", "-- Tags":
				lhs, tags, ok := strings.Cut(rhs, ":")
				if !ok {
					return Advisory{}, errors.Errorf("unexpected tags format. expected: %q, actual: %q", "(-- )Tags_<package>(_<release>): <tags>", line)
				}

				lhs, rhs, ok := strings.Cut(lhs, "_")
				if ok {
					if a.Packages == nil {
						a.Packages = make(map[string]Package)
					}
					base := a.Packages[lhs]
					if base.Releases == nil {
						base.Releases = make(map[string]Release)
					}
					release, ok := base.Releases[rhs]
					if ok {
						if len(release.Tags) > 0 {
							return Advisory{}, errors.Errorf("duplicate tags for release %s package %s", rhs, lhs)
						}
					}
					release.Tags = strings.Fields(strings.TrimSpace(tags))
					base.Releases[rhs] = release
					a.Packages[lhs] = base
				} else {
					if a.Packages == nil {
						a.Packages = make(map[string]Package)
					}
					base, ok := a.Packages[lhs]
					if ok {
						if len(base.Tags) > 0 {
							return Advisory{}, errors.Errorf("duplicate tags for package %s", lhs)
						}
					}
					base.Tags = strings.Fields(strings.TrimSpace(tags))
					a.Packages[lhs] = base
				}
			default:
				pkg, rhs, ok := strings.Cut(rhs, ":")
				if !ok {
					return Advisory{}, errors.Errorf("unexpected package status format. expected: %q, actual: %q", "<release>_<package>: <status>", line)
				}

				status, note, _ := strings.Cut(strings.TrimSpace(rhs), " ")
				if !slices.Contains([]string{"DNE", "needs-triage", "not-affected", "needed", "in-progress", "ignored", "pending", "deferred", "released"}, status) {
					log.Printf("[WARN] unexpected package status in %s. expected: %q, actual: %q", a.Candidate, []string{"DNE", "needs-triage", "not-affected", "needed", "in-progress", "ignored", "pending", "deferred", "released"}, status)
					break
				}

				if a.Packages == nil {
					a.Packages = make(map[string]Package)
				}
				base := a.Packages[pkg]
				if base.Releases == nil {
					base.Releases = make(map[string]Release)
				}
				release, ok := base.Releases[lhs]
				if ok {
					if release.Status != "" {
						return Advisory{}, errors.Errorf("duplicate status for release %s package %s", lhs, pkg)
					}
				}
				release.Status = status
				release.Note = strings.TrimPrefix(strings.TrimSuffix(note, ")"), "(")
				base.Releases[lhs] = release
				a.Packages[pkg] = base
			}
		}
	}

	return a, nil
}
