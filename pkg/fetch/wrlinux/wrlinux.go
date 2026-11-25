package wrlinux

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/filepath"
)

const defaultRepoURL = "https://distro.windriver.com/git/windriver-cve-tracker.git"

// templateLines are lines upstream never filled in. They name no release,
// package or status, so they are skipped in the files templateFiles lists.
var templateLines = []string{
	"{recipe_rcpl}_{package}: {status}",
	"{package}_{vendor_pr}: {status_vendor_pr}",
}

// templateFiles lists the files that carry templateLines in their Patches_
// sections: 17 under active/ at upstream commit 0acad29a2 (2026-11-23), with
// 148 such lines between them. It is a stopgap until upstream fills them in: a
// listed file without such a line fails the fetch, so its entry is removed
// rather than left behind, and such a line in a file that is not listed fails
// as any unknown status does.
var templateFiles = map[string]struct{}{
	"CVE-2002-0640":  {},
	"CVE-2002-1592":  {},
	"CVE-2003-0693":  {},
	"CVE-2005-3590":  {},
	"CVE-2005-4808":  {},
	"CVE-2006-5331":  {},
	"CVE-2006-7254":  {},
	"CVE-2006-20001": {},
	"CVE-2007-1804":  {},
	"CVE-2007-1864":  {},
	"CVE-2007-6761":  {},
	"CVE-2009-5147":  {},
	"CVE-2009-5155":  {},
	"CVE-2010-2496":  {},
	"CVE-2010-5312":  {},
	"CVE-2010-5321":  {},
	"CVE-2010-5332":  {},
}

type options struct {
	dir   string
	retry int

	// repoURL is only ever set by WithRepoURL, which lives in export_test.go
	// and is therefore absent from the production build.
	repoURL string
}

type Option interface {
	apply(*options)
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
		dir:     filepath.Join(util.CacheDir(), "fetch", "wrlinux"),
		retry:   3,
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Fetch Wind River Linux CVE Tracker")
	cloneDir, err := os.MkdirTemp("", "vuls-data-update")
	if err != nil {
		return errors.Wrapf(err, "mkdir %s", cloneDir)
	}
	defer os.RemoveAll(cloneDir)

	if err := exec.Command("git", "clone", "--depth", "1", options.repoURL, cloneDir).Run(); err != nil {
		return errors.Wrapf(err, "git clone --depth 1 %s %s", options.repoURL, cloneDir)
	}

	for _, target := range []string{"active", "retired"} {
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

			_, templated := templateFiles[base]
			v, skipped, err := parse(f, templated)
			if err != nil {
				return errors.Wrapf(err, "parse %s", path)
			}
			if templated && !skipped {
				return errors.Errorf("%s has no line of templateLines any more; remove it from templateFiles", path)
			}

			splitted, err := util.Split(v.Candidate, "-", "-")
			if err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.Candidate)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", v.Candidate)
			}

			p, err := utilfilepath.Join(options.dir, splitted[1], fmt.Sprintf("%s.json", v.Candidate))
			if err != nil {
				return errors.Wrap(err, "join")
			}

			if err := util.Write(p, v, util.WithAllowInvalidUTF8(true)); err != nil {
				return errors.Wrapf(err, "write %s", p)
			}

			return nil
		}); err != nil {
			return errors.Wrapf(err, "walk %s", filepath.Join(cloneDir, target))
		}
	}

	if err := util.EnsureWritten(options.dir); err != nil {
		return errors.Wrapf(err, "ensure written %s", options.dir)
	}

	return nil
}

func parse(r io.Reader, skipTemplate bool) (Vulnerability, bool, error) {
	vuln := Vulnerability{}
	skipped := false

	bs, err := io.ReadAll(r)
	if err != nil {
		return Vulnerability{}, false, errors.Wrap(err, "read all")
	}

	lines := strings.Split(string(bs), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "CRD:"):
			vuln.CRD = strings.TrimSpace(strings.TrimPrefix(line, "CRD:"))
		case strings.HasPrefix(line, "Candidate:"):
			vuln.Candidate = strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
		case strings.HasPrefix(line, "PublicDate:"):
			vuln.PublicDate = strings.TrimSpace(strings.TrimPrefix(line, "PublicDate:"))
		case strings.HasPrefix(line, "References:"):
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
				i++
				vuln.References = append(vuln.References, strings.TrimSpace(lines[i]))
			}
		case strings.HasPrefix(line, "ReleaseVersions:"):
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
				i++
				vuln.ReleaseVersions = append(vuln.ReleaseVersions, strings.TrimSpace(lines[i]))
			}
		case strings.HasPrefix(line, "Description:"):
			var description []string
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
				i++
				description = append(description, strings.TrimSpace(lines[i]))
			}
			vuln.Description = strings.Join(description, " ")
		case strings.HasPrefix(line, "WindRiver-Description:"):
			var description []string
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
				i++
				description = append(description, strings.TrimSpace(lines[i]))
			}
			vuln.WindRiverDescription = strings.Join(description, " ")
		case strings.HasPrefix(line, "Notes:"):
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
				i++
				note := []string{strings.TrimSpace(lines[i])}
				for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  ") {
					i++
					note = append(note, strings.TrimSpace(lines[i]))
				}
				vuln.Notes = append(vuln.Notes, strings.Join(note, " "))
			}
		case strings.HasPrefix(line, "Bugs:"):
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], " ") {
				i++
				vuln.Bugs = append(vuln.Bugs, strings.TrimSpace(lines[i]))
			}
		case strings.HasPrefix(line, "Priority:"):
			vuln.Priority = strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))
		case strings.HasPrefix(line, "Patches_"):
			if vuln.Patches == nil {
				vuln.Patches = make(map[Package]Statuses)
			}
			if vuln.UpstreamLinks == nil {
				vuln.UpstreamLinks = make(map[Package][]string)
			}

			name := Package(strings.TrimPrefix(strings.TrimSuffix(line, ":"), "Patches_"))
			if vuln.Patches[name] == nil {
				vuln.Patches[name] = make(Statuses)
			}

			for i+1 < len(lines) && lines[i+1] != "" {
				i++
				line := lines[i]

				switch {
				case strings.HasPrefix(line, " upstream:"):
					vuln.UpstreamLinks[name] = append(vuln.UpstreamLinks[name], strings.TrimSpace(strings.TrimPrefix(line, " upstream:")))
				case skipTemplate && slices.Contains(templateLines, line):
					skipped = true
				default:
					// ": " and not ":", since a package can be named with colons, as
					// HarfBuzz::Shaper is.
					lhs, rhs, ok := strings.Cut(line, ": ")
					if !ok {
						return Vulnerability{}, false, errors.Errorf("unexpected package status format. expected: %q, actual: %q", "<release>_<package>: <status> (<note>)", line)
					}

					r, n, ok := strings.Cut(lhs, "_")
					if !ok {
						return Vulnerability{}, false, errors.Errorf("unexpected package release format. expected: %q, actual: %q", "<release>_<package>", line)
					}
					// Only the section's own package has a map to write into.
					if Package(n) != name {
						return Vulnerability{}, false, errors.Errorf("unexpected package. expected: %q, actual: %q", name, n)
					}

					status, note, _ := strings.Cut(strings.TrimSpace(rhs), " ")
					switch status {
					case "released", "needed", "ignored", "DNE", "not-affected", "needs-triage", "deferred", "pending":
						vuln.Patches[name][Release(r)] = Status{
							Status: status,
							Note:   strings.TrimPrefix(strings.TrimSuffix(note, ")"), "("),
						}
					default:
						return Vulnerability{}, false, errors.Errorf("unexpected package status. expected: %q, actual: %q", []string{"released", "needed", "ignored", "DNE", "not-affected", "needs-triage", "deferred", "pending"}, status)
					}
				}
			}
		default:
			return Vulnerability{}, false, errors.Errorf("unexpected line format. expected: %q, actual: %q", []string{"CRD:...", "Candidate:...", "PublicDate:...", "References:...", "ReleaseVersions:...", "Description:...", "WindRiver-Description:...", "Notes:...", "Bugs:...", "Priority:...", "Patches_<package>:..."}, line)
		}
	}

	return vuln, skipped, nil
}
