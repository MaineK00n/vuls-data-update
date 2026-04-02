package cve

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/cve"
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
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "cve"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract RedHat CVE")

	br := utiljson.NewJSONReader()

	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		r := br.Copy()
		var fetched cve.CVE
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		splitted, err := util.Split(fetched.Name, "-", "-")
		if err != nil {
			return errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", "CVE-yyyy-\\d{4,}", fetched.Name)
		}

		if err := util.Write(filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", fetched.Name)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", splitted[1], fmt.Sprintf("%s.json", fetched.Name)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.RedHatCVE,
		Name: new("RedHat Security Data API"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r != nil {
				return []repositoryTypes.Repository{*r}
			}
			return nil
		}(),
		Extracted: func() *repositoryTypes.Repository {
			if u, err := utilgit.GetOrigin(options.dir); err == nil {
				return &repositoryTypes.Repository{URL: u}
			}
			return nil
		}(),
	}, false); err != nil {
		return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "datasource.json"))
	}

	return nil
}

// This extractor intentionally does not produce Detections.
//
// The Red Hat CVE API (Security Data API) provides two types of package information:
//
//  1. affected_release: Lists fixed packages in NEVRA format (e.g. "curl-0:8.6.0-3.el9")
//     alongside a CPE identifying the product (e.g. "cpe:/o:redhat:enterprise_linux:9").
//     However, ~7% of entries use modular package format (e.g. "redis:7-9050020250115104757.9"),
//     which identifies the module stream, not individual RPM source packages. Since the API does
//     not provide the list of component packages within a module, these entries cannot be
//     translated into actionable version criterions.
//
//  2. package_state: Lists package names with a fix_state (e.g. "Affected", "Will not fix").
//     These have no version constraints because the packages are unfixed, meaning all versions
//     are affected. This data could be used for detection (package name match with Affected=nil),
//     but is not currently extracted because it shares the same CPE/ecosystem ambiguity issues.
//
// CPEs for layered products (e.g. "cpe:/a:redhat:logging:5.8::el9") refer to container images
// and other non-RPM artifacts, not traditional RPM packages. Only RHEL base CPEs
// (enterprise_linux, rhel_eus, etc.) reliably correspond to RPM packages, but even those
// suffer from the modular package problem in affected_release.
//
// For reliable detection of Red Hat vulnerabilities, use the CSAF, VEX, or OVAL data sources
// instead, which provide complete and structured product-package mappings.
func extract(fetched cve.CVE, raws []string) (dataTypes.Data, error) {
	ss, err := buildSeverities(fetched)
	if err != nil {
		return dataTypes.Data{}, errors.Wrap(err, "build severities")
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.Name),
		Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
			Content: vulnerabilityContentTypes.Content{
				ID:          vulnerabilityContentTypes.VulnerabilityID(fetched.Name),
				Title:       fetched.Bugzilla.Description,
				Description: strings.Join(fetched.Details, "\n"),
				Severity:    ss,
				CWE:         buildCWE(fetched),
				References:  buildReferences(fetched),
				Published:   utiltime.Parse([]string{"2006-01-02T15:04:05Z"}, fetched.PublicDate),
			},
		}},
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.RedHatCVE,
			Raws: raws,
		},
	}, nil
}

func buildSeverities(fetched cve.CVE) ([]severityTypes.Severity, error) {
	var ss []severityTypes.Severity

	if fetched.Cvss != nil && fetched.Cvss.CvssScoringVector != "" {
		v2, err := cvssV2Types.Parse(fetched.Cvss.CvssScoringVector)
		if err != nil {
			return nil, errors.Wrapf(err, "parse cvss v2. vector: %s", fetched.Cvss.CvssScoringVector)
		}
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeCVSSv2,
			Source: "secalert@redhat.com",
			CVSSv2: v2,
		})
	}

	if fetched.Cvss3 != nil && fetched.Cvss3.Cvss3ScoringVector != "" {
		switch {
		case strings.HasPrefix(fetched.Cvss3.Cvss3ScoringVector, "CVSS:3.0"):
			v30, err := cvssV30Types.Parse(fetched.Cvss3.Cvss3ScoringVector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss v3.0. vector: %s", fetched.Cvss3.Cvss3ScoringVector)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv30,
				Source:  "secalert@redhat.com",
				CVSSv30: v30,
			})
		case strings.HasPrefix(fetched.Cvss3.Cvss3ScoringVector, "CVSS:3.1"):
			v31, err := cvssV31Types.Parse(fetched.Cvss3.Cvss3ScoringVector)
			if err != nil {
				return nil, errors.Wrapf(err, "parse cvss v3.1. vector: %s", fetched.Cvss3.Cvss3ScoringVector)
			}
			ss = append(ss, severityTypes.Severity{
				Type:    severityTypes.SeverityTypeCVSSv31,
				Source:  "secalert@redhat.com",
				CVSSv31: v31,
			})
		default:
			return nil, errors.Errorf("unexpected CVSS v3 vector. expected: %q, actual: %q", []string{"CVSS:3.0/...", "CVSS:3.1/..."}, fetched.Cvss3.Cvss3ScoringVector)
		}
	}

	if fetched.ThreatSeverity != nil {
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeVendor,
			Source: "secalert@redhat.com",
			Vendor: fetched.ThreatSeverity,
		})
	}

	return ss, nil
}

func buildCWE(fetched cve.CVE) []cweTypes.CWE {
	if fetched.Cwe == nil || *fetched.Cwe == "" {
		return nil
	}
	return []cweTypes.CWE{{
		Source: "secalert@redhat.com",
		CWE:    []string{*fetched.Cwe},
	}}
}

func buildReferences(fetched cve.CVE) []referenceTypes.Reference {
	var refs []referenceTypes.Reference

	if fetched.Bugzilla.URL != "" {
		refs = append(refs, referenceTypes.Reference{
			Source: "secalert@redhat.com",
			URL:    fetched.Bugzilla.URL,
		})
	}

	for _, r := range fetched.References {
		for u := range strings.SplitSeq(r, "\n") {
			u = strings.TrimSpace(u)
			if u != "" {
				refs = append(refs, referenceTypes.Reference{
					Source: "secalert@redhat.com",
					URL:    u,
				})
			}
		}
	}

	return refs
}
