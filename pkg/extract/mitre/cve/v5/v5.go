package v5

import (
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	v40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	ssvcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/ssvc"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
	utilgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	utiljson "github.com/MaineK00n/vuls-data-update/pkg/extract/util/json"
	utiltime "github.com/MaineK00n/vuls-data-update/pkg/extract/util/time"
	v5 "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/cve/v5"
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
		dir: filepath.Join(util.CacheDir(), "extract", "mitre", "cve", "v5"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	slog.Info("Extract MITRE CVE v5")
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
		var fetched v5.CVE
		if err := r.Read(path, args, &fetched); err != nil {
			return errors.Wrapf(err, "read json %s", path)
		}

		extracted, err := extract(fetched, r.Paths())
		if err != nil {
			return errors.Wrapf(err, "extracted %s", path)
		}

		if err := util.Write(filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)), extracted, true); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, "data", filepath.Base(filepath.Dir(path)), fmt.Sprintf("%s.json", extracted.ID)))
		}

		return nil
	}); err != nil {
		return errors.Wrapf(err, "walk %s", args)
	}

	if err := util.Write(filepath.Join(options.dir, "datasource.json"), datasourceTypes.DataSource{
		ID:   sourceTypes.MitreCVEV5,
		Name: new("MITRE CVE v5"),
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

func extract(fetched v5.CVE, raws []string) (dataTypes.Data, error) {
	switch fetched.CVEMetadata.State {
	case "PUBLISHED":
		severities, err := func() ([]severityTypes.Severity, error) {
			m := make(map[string][]v5.Metric)
			m[getSource(fetched.Containers.CNA.ProviderMetadata)] = append(m[getSource(fetched.Containers.CNA.ProviderMetadata)], fetched.Containers.CNA.Metrics...)
			for _, c := range fetched.Containers.ADP {
				m[getSource(c.ProviderMetadata)] = append(m[getSource(c.ProviderMetadata)], c.Metrics...)
			}
			var ss []severityTypes.Severity
			for source, ms := range m {
				for _, metric := range ms {
					if metric.CVSSv2 != nil {
						v2, err := v2Types.Parse(metric.CVSSv2.VectorString)
						if err != nil {
							return nil, errors.Wrapf(err, "parse cvss v2 vector %s", metric.CVSSv2.VectorString)
						}
						ss = append(ss, severityTypes.Severity{
							Type:   severityTypes.SeverityTypeCVSSv2,
							Source: source,
							CVSSv2: v2,
						})
					}
					if metric.CVSSv30 != nil {
						v30, err := v30Types.Parse(metric.CVSSv30.VectorString)
						if err != nil {
							return nil, errors.Wrapf(err, "parse cvss v3.0 vector %s", metric.CVSSv30.VectorString)
						}
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv30,
							Source:  source,
							CVSSv30: v30,
						})
					}
					if metric.CVSSv31 != nil {
						v31, err := v31Types.Parse(metric.CVSSv31.VectorString)
						if err != nil {
							return nil, errors.Wrapf(err, "parse cvss v3.1 vector %s", metric.CVSSv31.VectorString)
						}
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv31,
							Source:  source,
							CVSSv31: v31,
						})
					}
					if metric.CVSSv40 != nil {
						v40, err := v40Types.Parse(metric.CVSSv40.VectorString)
						if err != nil {
							return nil, errors.Wrapf(err, "parse cvss v4.0 vector %s", metric.CVSSv40.VectorString)
						}
						ss = append(ss, severityTypes.Severity{
							Type:    severityTypes.SeverityTypeCVSSv40,
							Source:  source,
							CVSSv40: v40,
						})
					}
				}
			}
			return ss, nil
		}()
		if err != nil {
			return dataTypes.Data{}, errors.Wrap(err, "parse severity")
		}

		ssvcs, err := func() ([]ssvcTypes.SSVC, error) {
			m := make(map[string][]v5.Metric)
			m[getSource(fetched.Containers.CNA.ProviderMetadata)] = append(m[getSource(fetched.Containers.CNA.ProviderMetadata)], fetched.Containers.CNA.Metrics...)
			for _, c := range fetched.Containers.ADP {
				m[getSource(c.ProviderMetadata)] = append(m[getSource(c.ProviderMetadata)], c.Metrics...)
			}
			var ss []ssvcTypes.SSVC
			for source, ms := range m {
				for _, metric := range ms {
					if metric.Other == nil || metric.Other.Type != "ssvc" {
						continue
					}
					var content v5.SSVC
					if err := json.Unmarshal(metric.Other.Content, &content); err != nil {
						return nil, errors.Wrap(err, "unmarshal ssvc content")
					}
					var options []ssvcTypes.Option
					for _, o := range content.Options {
						mo, ok := o.(map[string]any)
						if !ok {
							return nil, errors.Errorf("unexpected ssvc option type %T", o)
						}
						for k, v := range mo {
							// Per the SSVC computed schema, an option value is a string or an array of strings.
							switch vs := v.(type) {
							case string:
								options = append(options, ssvcTypes.Option{
									Key:   k,
									Value: vs,
								})
							case []any:
								for _, e := range vs {
									s, ok := e.(string)
									if !ok {
										return nil, errors.Errorf("unexpected ssvc option value type %T for key %q", e, k)
									}
									options = append(options, ssvcTypes.Option{
										Key:   k,
										Value: s,
									})
								}
							default:
								return nil, errors.Errorf("unexpected ssvc option value type %T for key %q", v, k)
							}
						}
					}
					ss = append(ss, ssvcTypes.SSVC{
						Source:    source,
						Role:      content.Role,
						Version:   content.Version,
						Options:   options,
						Timestamp: utiltime.Parse([]string{"2006-01-02T15:04:05.999999999Z07:00"}, content.Timestamp),
					})
				}
			}
			return ss, nil
		}()
		if err != nil {
			return dataTypes.Data{}, errors.Wrap(err, "parse ssvc")
		}

		return dataTypes.Data{
			ID: dataTypes.RootID(fetched.CVEMetadata.CVEID),
			Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(fetched.CVEMetadata.CVEID),
					Title: func() string {
						if fetched.Containers.CNA.Title != nil {
							return *fetched.Containers.CNA.Title
						}
						return ""
					}(),
					Description: func() string {
						for _, d := range fetched.Containers.CNA.Descriptions {
							if d.Lang == "en" {
								return d.Value
							}
						}
						return ""
					}(),
					Severity: severities,
					CWE: func() []cweTypes.CWE {
						m := make(map[string][]v5.ProblemType)
						m[getSource(fetched.Containers.CNA.ProviderMetadata)] = append(m[getSource(fetched.Containers.CNA.ProviderMetadata)], fetched.Containers.CNA.ProblemTypes...)
						for _, c := range fetched.Containers.ADP {
							m[getSource(c.ProviderMetadata)] = append(m[getSource(c.ProviderMetadata)], c.ProblemTypes...)
						}

						mm := make(map[string][]string)
						for source, ps := range m {
							for _, p := range ps {
								for _, d := range p.Descriptions {
									if d.CweID != nil {
										mm[source] = append(mm[source], *d.CweID)
									}
								}
							}
						}

						cwes := make([]cweTypes.CWE, 0, len(mm))
						for source, cs := range mm {
							cwes = append(cwes, cweTypes.CWE{
								Source: source,
								CWE:    cs,
							})
						}
						return cwes
					}(),
					Workarounds: func() []remediationTypes.Remediation {
						m := make(map[string][]v5.Description)
						m[getSource(fetched.Containers.CNA.ProviderMetadata)] = append(m[getSource(fetched.Containers.CNA.ProviderMetadata)], fetched.Containers.CNA.Workarounds...)
						for _, c := range fetched.Containers.ADP {
							m[getSource(c.ProviderMetadata)] = append(m[getSource(c.ProviderMetadata)], c.Workarounds...)
						}

						var rs []remediationTypes.Remediation
						for source, ws := range m {
							for _, w := range ws {
								if (w.Lang != "" && w.Lang != "en") || w.Value == "" {
									continue
								}
								rs = append(rs, remediationTypes.Remediation{
									Source:      source,
									Description: w.Value,
								})
							}
						}
						return rs
					}(),
					References: func() []referenceTypes.Reference {
						m := make(map[string][]v5.Reference)
						m[getSource(fetched.Containers.CNA.ProviderMetadata)] = append(m[getSource(fetched.Containers.CNA.ProviderMetadata)], fetched.Containers.CNA.References...)
						for _, c := range fetched.Containers.ADP {
							m[getSource(c.ProviderMetadata)] = append(m[getSource(c.ProviderMetadata)], c.References...)
						}

						var refs []referenceTypes.Reference
						for source, rs := range m {
							for _, r := range rs {
								refs = append(refs, referenceTypes.Reference{
									Source: source,
									URL:    r.URL,
								})
							}
						}
						return refs
					}(),
					SSVC: ssvcs,
					Published: func() *time.Time {
						if fetched.CVEMetadata.DatePublished != nil {
							return utiltime.Parse([]string{"2006-01-02T15:04:05.000Z"}, *fetched.CVEMetadata.DatePublished)
						}
						return nil
					}(),
					Modified: func() *time.Time {
						if fetched.CVEMetadata.DateUpdated != nil {
							return utiltime.Parse([]string{"2006-01-02T15:04:05.000Z"}, *fetched.CVEMetadata.DateUpdated)
						}
						return nil
					}(),
					Optional: func() map[string]any {
						// Map each source label (provider shortName) to the
						// container that produced it. CNA/ADP is determined by
						// structural position, not by any source-string suffix.
						cts := make(map[string]string)
						cts[getSource(fetched.Containers.CNA.ProviderMetadata)] = "CNA"
						for _, c := range fetched.Containers.ADP {
							cts[getSource(c.ProviderMetadata)] = "ADP"
						}
						return map[string]any{"container_types": cts}
					}(),
				},
			}},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MitreCVEV5,
				Raws: raws,
			},
		}, nil
	case "REJECTED":
		return dataTypes.Data{
			ID: dataTypes.RootID(fetched.CVEMetadata.CVEID),
			Vulnerabilities: []vulnerabilityTypes.Vulnerability{{
				Content: vulnerabilityContentTypes.Content{
					ID: vulnerabilityContentTypes.VulnerabilityID(fetched.CVEMetadata.CVEID),
					Title: func() string {
						if fetched.Containers.CNA.Title != nil {
							return *fetched.Containers.CNA.Title
						}
						return ""
					}(),
					Description: func() string {
						for _, d := range fetched.Containers.CNA.RejectedReasons {
							if d.Lang == "en" {
								return d.Value
							}
						}
						return ""
					}(),
					Published: func() *time.Time {
						if fetched.CVEMetadata.DatePublished != nil {
							return utiltime.Parse([]string{"2006-01-02T15:04:05.000Z"}, *fetched.CVEMetadata.DatePublished)
						}
						return nil
					}(),
					Modified: func() *time.Time {
						if fetched.CVEMetadata.DateRejected != nil {
							return utiltime.Parse([]string{"2006-01-02T15:04:05.000Z"}, *fetched.CVEMetadata.DateRejected)
						}
						return nil
					}(),
				},
			}},
			DataSource: sourceTypes.Source{
				ID:   sourceTypes.MitreCVEV5,
				Raws: raws,
			},
		}, nil
	default:
		return dataTypes.Data{}, errors.Errorf("unexpected CVE state. expected: %q, actual: %q", []string{"PUBLISHED", "REJECTED"}, fetched.CVEMetadata.State)
	}
}

func getSource(providerMetadata v5.ProviderMetadata) string {
	if providerMetadata.ShortName != nil {
		return *providerMetadata.ShortName
	}
	return providerMetadata.OrgID
}
