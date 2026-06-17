package json

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	asaVersion "github.com/MaineK00n/go-cisco-version/asa"
	fmcVersion "github.com/MaineK00n/go-cisco-version/fmc"
	ftdVersion "github.com/MaineK00n/go-cisco-version/ftd"
	fxosVersion "github.com/MaineK00n/go-cisco-version/fxos"
	iosVersion "github.com/MaineK00n/go-cisco-version/ios"
	iosxeVersion "github.com/MaineK00n/go-cisco-version/ios-xe"
	iosxrVersion "github.com/MaineK00n/go-cisco-version/ios-xr"
	nxosVersion "github.com/MaineK00n/go-cisco-version/nx-os"
	wlcVersion "github.com/MaineK00n/go-cisco-version/wlc"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	fetchTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/cisco/json"
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
		dir: filepath.Join(util.CacheDir(), "extract", "cisco", "json"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract Cisco JSON")
	if err := filepath.WalkDir(args, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r := utiljson.NewJSONReader()
		var fetched fetchTypes.Advisory
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read %s", path)
		}

		data, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extract %s", path)
		}

		t := utiltime.Parse([]string{"2006-01-02T15:04:05"}, fetched.FirstPublished)
		if t == nil {
			return errors.Errorf("unexpected firstPublished format. expected: %q, actual: %q", "2006-01-02T15:04:05", fetched.FirstPublished)
		}

		if err := util.Write(filepath.Join(options.dir, "data", fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", data.ID)), data, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", fmt.Sprintf("%d", t.Year()), fmt.Sprintf("%s.json", data.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.CiscoJSON,
		Name: new("Cisco Security Advisories: openVuln API"),
		Raw: func() []repositoryTypes.Repository {
			r, _ := utilgit.GetDataSourceRepository(args)
			if r == nil {
				return nil
			}
			return []repositoryTypes.Repository{*r}
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

func extract(fetched fetchTypes.Advisory, raws []string) (dataTypes.Data, error) {
	if fetched.AdvisoryID == "" {
		return dataTypes.Data{}, errors.New("advisoryId is empty")
	}

	// Build vendor severity from SIR (Security Impact Rating)
	var ss []severityTypes.Severity
	if fetched.Sir != "NA" {
		ss = append(ss, severityTypes.Severity{
			Type:   severityTypes.SeverityTypeVendor,
			Source: "cisco.com",
			Vendor: &fetched.Sir,
		})
	}

	// Build CWE
	var cweIDs []string
	for _, c := range fetched.Cwe {
		if c == "NA" || slices.Contains(cweIDs, c) {
			continue
		}
		cweIDs = append(cweIDs, c)
	}
	var cwes []cweTypes.CWE
	if len(cweIDs) > 0 {
		cwes = []cweTypes.CWE{{
			Source: "cisco.com",
			CWE:    cweIDs,
		}}
	}

	// Build references from advisory URLs and bug IDs
	var refs []referenceTypes.Reference
	for _, u := range []string{fetched.PublicationURL, fetched.CsafURL, fetched.CvrfURL} {
		if u == "NA" {
			continue
		}
		refs = append(refs, referenceTypes.Reference{
			Source: "cisco.com",
			URL:    u,
		})
	}
	for _, b := range fetched.BugIDs {
		if b == "NA" {
			continue
		}
		refs = append(refs, referenceTypes.Reference{
			Source: "cisco.com",
			URL:    fmt.Sprintf("https://bst.cloudapps.cisco.com/bugsearch/bug/%s", b),
		})
	}

	// Build CPE-based detections from product names
	var criterions []criterionTypes.Criterion
	converted := make(map[string]struct{})
	for _, p := range fetched.ProductNames {
		if p == "NA" {
			continue
		}
		cpe, err := convertProductName(p)
		if err != nil {
			slog.Warn("failed to convert product name to CPE", slog.String("name", p), slog.Any("err", err))
			continue
		}
		if cpe == "" {
			continue
		}
		if _, ok := converted[cpe]; ok {
			continue
		}
		converted[cpe] = struct{}{}
		criterions = append(criterions, criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeCPE,
			CPE: &ccTypes.Criterion{
				Vulnerable: true,
				CPE:        ccTypes.CPE(cpe),
			},
		})
	}

	var segments []segmentTypes.Segment
	var detections []detectionTypes.Detection
	if len(criterions) > 0 {
		segments = []segmentTypes.Segment{{
			Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		}}
		detections = []detectionTypes.Detection{{
			Ecosystem: ecosystemTypes.EcosystemTypeCPE,
			Conditions: []conditionTypes.Condition{{
				Criteria: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: criterions,
				},
			}},
		}}
	}

	// Build vulnerabilities from CVEs. Advisories without valid CVEs yield
	// advisory-only data (no vulnerability records are fabricated).
	var vulns []vulnerabilityTypes.Vulnerability
	for _, cve := range fetched.Cves {
		if cve == "NA" || slices.ContainsFunc(vulns, func(v vulnerabilityTypes.Vulnerability) bool {
			return v.Content.ID == vulnerabilityContentTypes.VulnerabilityID(cve)
		}) {
			continue
		}
		vulns = append(vulns, vulnerabilityTypes.Vulnerability{
			Content: vulnerabilityContentTypes.Content{
				ID: vulnerabilityContentTypes.VulnerabilityID(cve),
			},
			Segments: segments,
		})
	}

	return dataTypes.Data{
		ID: dataTypes.RootID(fetched.AdvisoryID),
		Advisories: []advisoryTypes.Advisory{{
			Content: advisoryContentTypes.Content{
				ID:          advisoryContentTypes.AdvisoryID(fetched.AdvisoryID),
				Title:       fetched.AdvisoryTitle,
				Description: fetched.Summary,
				Severity:    ss,
				CWE:         cwes,
				References:  refs,
				Published:   utiltime.Parse([]string{"2006-01-02T15:04:05"}, fetched.FirstPublished),
				Modified:    utiltime.Parse([]string{"2006-01-02T15:04:05"}, fetched.LastUpdated),
			},
			Segments: segments,
		}},
		Vulnerabilities: vulns,
		Detections:      detections,
		DataSource: sourceTypes.Source{
			ID:   sourceTypes.CiscoJSON,
			Raws: raws,
		},
	}, nil
}

type productConversion struct {
	prefix string
	skips  []string
	cpe    string
	parse  func(string) (string, error)
}

// productConversions maps Cisco product name prefixes to CPE bases. Order
// matters: more specific prefixes (e.g. "Cisco IOS XE ...") must come before
// less specific ones (e.g. "Cisco IOS "). The table mirrors
// go-cve-dictionary's fetcher/cisco conversion, extended with the renamed
// "Cisco Secure Firewall ..." product names.
var productConversions = []productConversion{
	{
		prefix: "Cisco Adaptive Security Appliance (ASA) Software ",
		skips:  []string{"", "Base"},
		cpe:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := asaVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software ",
		skips:  []string{"", "Base"},
		cpe:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := asaVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco Firepower Extensible Operating System (FXOS) ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:firepower_extensible_operating_system:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := fxosVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco Firepower Management Center ",
		skips:  []string{"", "Base"},
		cpe:    "cpe:2.3:a:cisco:secure_firewall_management_center:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := fmcVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco Secure Firewall Management Center (FMC) ",
		skips:  []string{"", "Base"},
		cpe:    "cpe:2.3:a:cisco:secure_firewall_management_center:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := fmcVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco Firepower Threat Defense Software ",
		skips:  []string{"", "for Firepower 1000/2100 Series"},
		cpe:    "cpe:2.3:a:cisco:firepower_threat_defense:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := ftdVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco Secure Firewall Threat Defense (FTD) Software ",
		skips:  []string{""},
		cpe:    "cpe:2.3:a:cisco:firepower_threat_defense:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := ftdVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS XE Catalyst SD-WAN ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosxeVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS XE SD-WAN Software ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosxeVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS XE ROMMON Software ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosxeVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS XE Software Bootloader (ROMMON) ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosxeVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS XE Software ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosxeVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS XR Software ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios_xr:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosxrVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS ROMMON Software ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco IOS ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := iosVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco NX-OS System Software in ACI Mode ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:nx-os:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := nxosVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco NX-OS Software ",
		skips:  []string{""},
		cpe:    "cpe:2.3:o:cisco:nx-os:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := nxosVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
	{
		prefix: "Cisco Wireless LAN Controller (WLC) ",
		skips:  []string{"", "Base"},
		cpe:    "cpe:2.3:o:cisco:wireless_lan_controller_software:*:*:*:*:*:*:*:*",
		parse: func(s string) (string, error) {
			v, err := wlcVersion.NewVersion(s)
			if err != nil {
				return "", err
			}
			return v.String(), nil
		},
	},
}

// convertProductName converts a Cisco product name to a CPE 2.3 formatted
// string with the exact version bound. It returns an empty string for
// product names that carry no detectable version ("Base", etc.) or belong to
// product families without an established CPE mapping.
func convertProductName(name string) (string, error) {
	for _, c := range productConversions {
		s, ok := strings.CutPrefix(name, c.prefix)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if slices.Contains(c.skips, s) {
			return "", nil
		}

		v, err := c.parse(s)
		if err != nil {
			return "", errors.Wrapf(err, "parse version %q", s)
		}

		wfn, err := naming.UnbindFS(c.cpe)
		if err != nil {
			return "", errors.Wrapf(err, "unbind %q", c.cpe)
		}
		if err := wfn.Set(common.AttributeVersion, strings.NewReplacer(".", "\\.", "-", "\\-", "(", "\\(", ")", "\\)").Replace(strings.ToLower(v))); err != nil {
			return "", errors.Wrapf(err, "set version %q", v)
		}

		return naming.BindToFS(wfn), nil
	}
	return "", nil
}
