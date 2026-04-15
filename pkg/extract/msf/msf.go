package msf

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	metasploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/metasploit"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/msf"
)

type options struct {
	dir string
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

func Extract(args string, opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "msf"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Metasploit Framework")

	cveModules := make(map[string]dataTypes.Data)

	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched msf.Module
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		cveIDs, refs, err := classifyReferences(fetched.References)
		if err != nil {
			return errors.Wrapf(err, "classify references for %s", path)
		}

		for _, cveID := range cveIDs {
			base, ok := cveModules[cveID]
			if !ok {
				base = dataTypes.Data{
					ID: dataTypes.RootID(cveID),
					Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID(cveID),
						},
					}},
					DataSource: sourceTypes.Source{
						ID: sourceTypes.Metasploit,
					},
				}
			}

			base.Vulnerabilities[0].Content.Metasploit = append(base.Vulnerabilities[0].Content.Metasploit, metasploitTypes.Metasploit{
				Type:        fetched.Type,
				Name:        fetched.Name,
				FullName:    fetched.Fullname,
				Aliases:     fetched.Aliases,
				Description: fetched.Description,
				Rank:        fetched.Rank,
				Author:      fetched.Author,
				Platform:    fetched.Platform,
				Arch:        fetched.Arch,
				Targets:     fetched.Targets,
				Published: func() time.Time {
					if t := utiltime.Parse([]string{"2006-01-02", "2006-01-02 15:04:05 -0700"}, fetched.DisclosureDate); t != nil {
						return *t
					}
					return time.Time{}
				}(),
				Modified: func() time.Time {
					if t := utiltime.Parse([]string{"2006-01-02", "2006-01-02 15:04:05 -0700"}, fetched.ModTime); t != nil {
						return *t
					}
					return time.Time{}
				}(),
				References: refs,
			})
			base.DataSource.Raws = append(base.DataSource.Raws, r.Paths()...)

			cveModules[cveID] = base
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	for cveID, data := range cveModules {
		splitted, err := util.Split(cveID, "-", "-")
		if err != nil {
			return errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cveID)
		}
		if _, err := time.Parse("2006", splitted[1]); err != nil {
			return errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", cveID)
		}
		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", cveID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", cveID)))
		}
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.Metasploit,
		Name: new("Metasploit Framework"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{
					URL: u,
				}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

// classifyReferences separates CVE IDs and other references from raw MSF reference strings.
// Raw references use prefixes: "CVE-YYYY-NNNN", "URL-https://...", "MSB-...", "EDB-...", etc.
func classifyReferences(refs []string) ([]string, []referenceTypes.Reference, error) {
	var (
		cveIDs     []string
		references []referenceTypes.Reference
	)
	for _, ref := range refs {
		switch {
		case strings.HasPrefix(ref, "CVE-"):
			splitted, err := util.Split(ref, "-", "-")
			if err != nil {
				return nil, nil, errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", ref)
			}
			if _, err := time.Parse("2006", splitted[1]); err != nil {
				return nil, nil, errors.Errorf("unexpected CVE ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", ref)
			}
			if !slices.Contains(cveIDs, ref) {
				cveIDs = append(cveIDs, ref)
			}
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", ref),
			})
		case strings.HasPrefix(ref, "URL-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    strings.TrimPrefix(ref, "URL-"),
			})
		case strings.HasPrefix(ref, "EDB-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://www.exploit-db.com/exploits/%s", strings.TrimPrefix(ref, "EDB-")),
			})
		case strings.HasPrefix(ref, "MSB-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/%s", strings.TrimPrefix(ref, "MSB-")),
			})
		case strings.HasPrefix(ref, "USN-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://ubuntu.com/security/notices/USN-%s", strings.TrimPrefix(ref, "USN-")),
			})
		case strings.HasPrefix(ref, "BID-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://www.securityfocus.com/bid/%s", strings.TrimPrefix(ref, "BID-")),
			})
		case strings.HasPrefix(ref, "ZDI-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://www.zerodayinitiative.com/advisories/%s", ref),
			})
		case strings.HasPrefix(ref, "PACKETSTORM-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://packetstormsecurity.com/files/%s", strings.TrimPrefix(ref, "PACKETSTORM-")),
			})
		case strings.HasPrefix(ref, "WPVDB-"):
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    fmt.Sprintf("https://wpscan.com/vulnerability/%s", strings.TrimPrefix(ref, "WPVDB-")),
			})
		default:
			u, err := url.Parse(ref)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return nil, nil, errors.Errorf("unknown reference format: %s", ref)
			}
			references = append(references, referenceTypes.Reference{
				Source: "rapid7/metasploit",
				URL:    ref,
			})
		}
	}
	return cveIDs, references, nil
}
