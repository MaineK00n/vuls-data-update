package data_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	v31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

func TestData_Sort(t *testing.T) {
	type fields struct {
		ID              dataTypes.RootID
		Advisories      []advisoryTypes.Advisory
		Vulnerabilities []vulnerabilityTypes.Vulnerability
		Detection       []detectionTypes.Detection
		DataSource      sourceTypes.Source
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &dataTypes.Data{
				ID:              tt.fields.ID,
				Advisories:      tt.fields.Advisories,
				Vulnerabilities: tt.fields.Vulnerabilities,
				Detections:      tt.fields.Detection,
				DataSource:      tt.fields.DataSource,
			}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x dataTypes.Data
		y dataTypes.Data
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dataTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestData_Merge(t *testing.T) {
	type args struct {
		ds []dataTypes.Data
	}
	tests := []struct {
		name     string
		fields   dataTypes.Data
		args     args
		expected dataTypes.Data
	}{
		// cases to merge advisories
		{
			name: "receiver's advisory is empty",
			fields: dataTypes.Data{
				ID:         dataTypes.RootID("id"),
				Advisories: nil,
			},
			args: args{
				ds: []dataTypes.Data{
					{
						ID: dataTypes.RootID("id"),
						Advisories: []advisoryTypes.Advisory{
							{
								Content: advisoryContentTypes.Content{
									ID: advisoryContentTypes.AdvisoryID("ADV-001"),
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ecosystem:1"},
								},
							},
						},
					},
				},
			},
			expected: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
		},
		{
			name: "args' advisory is empty",
			fields: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
			args: args{
				ds: []dataTypes.Data{
					{
						ID:         dataTypes.RootID("id"),
						Advisories: nil,
					},
				},
			},
			expected: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
		},
		{
			name: "merge advisories",
			fields: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-101"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.2"},
						},
					},
				},
			},
			args: args{
				ds: []dataTypes.Data{
					{
						ID: dataTypes.RootID("id"),
						Advisories: []advisoryTypes.Advisory{
							{
								Content: advisoryContentTypes.Content{
									ID: advisoryContentTypes.AdvisoryID("ADV-201"),
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ecosystem:2.1"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: advisoryContentTypes.AdvisoryID("ADV-001"),
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ecosystem:2.2"},
								},
							},
						},
					},
				},
			},
			expected: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
							{Ecosystem: "ecosystem:2.2"},
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-101"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.2"},
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-201"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:2.1"},
						},
					},
				},
			},
		},
		{
			// Regression case for Merge's Sort normalization: the same advisory
			// content carries its severities in a different non-canonical order
			// on each side (canonical: vendor, cvss_v2, cvss_v31). The two raw
			// orders also differ from each other, so the match succeeds only if
			// BOTH d.Sort() and e.Sort() run — dropping either one makes this
			// case duplicate the advisory instead of merging it.
			name: "same advisory with severities in different non-canonical orders",
			fields: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-001"),
							Severity: []severityTypes.Severity{
								{
									Type:    severityTypes.SeverityTypeCVSSv31,
									Source:  "vendor",
									CVSSv31: &v31Types.CVSSv31{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8, BaseSeverity: "CRITICAL"},
								},
								{
									Type:   severityTypes.SeverityTypeVendor,
									Source: "vendor",
									Vendor: new("Critical"),
								},
								{
									Type:   severityTypes.SeverityTypeCVSSv2,
									Source: "vendor",
									CVSSv2: &v2Types.CVSSv2{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", BaseScore: 10, NVDBaseSeverity: "HIGH"},
								},
							},
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
			args: args{
				ds: []dataTypes.Data{
					{
						ID: dataTypes.RootID("id"),
						Advisories: []advisoryTypes.Advisory{
							{
								Content: advisoryContentTypes.Content{
									ID: advisoryContentTypes.AdvisoryID("ADV-001"),
									Severity: []severityTypes.Severity{
										{
											Type:   severityTypes.SeverityTypeCVSSv2,
											Source: "vendor",
											CVSSv2: &v2Types.CVSSv2{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", BaseScore: 10, NVDBaseSeverity: "HIGH"},
										},
										{
											Type:    severityTypes.SeverityTypeCVSSv31,
											Source:  "vendor",
											CVSSv31: &v31Types.CVSSv31{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8, BaseSeverity: "CRITICAL"},
										},
										{
											Type:   severityTypes.SeverityTypeVendor,
											Source: "vendor",
											Vendor: new("Critical"),
										},
									},
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ecosystem:2"},
								},
							},
						},
					},
				},
			},
			expected: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: advisoryContentTypes.AdvisoryID("ADV-001"),
							Severity: []severityTypes.Severity{
								{
									Type:   severityTypes.SeverityTypeVendor,
									Source: "vendor",
									Vendor: new("Critical"),
								},
								{
									Type:   severityTypes.SeverityTypeCVSSv2,
									Source: "vendor",
									CVSSv2: &v2Types.CVSSv2{Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", BaseScore: 10, NVDBaseSeverity: "HIGH"},
								},
								{
									Type:    severityTypes.SeverityTypeCVSSv31,
									Source:  "vendor",
									CVSSv31: &v31Types.CVSSv31{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8, BaseSeverity: "CRITICAL"},
								},
							},
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
							{Ecosystem: "ecosystem:2"},
						},
					},
				},
			},
		},
		// cases to merge vulnerablities
		{
			name: "receiver's vulnerability is empty",
			fields: dataTypes.Data{
				ID:              dataTypes.RootID("id"),
				Vulnerabilities: nil,
			},
			args: args{
				ds: []dataTypes.Data{{
					ID: dataTypes.RootID("id"),
					Vulnerabilities: []vulnerabilityTypes.Vulnerability{
						{
							Content: vulnerabilityContentTypes.Content{
								ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-0001"),
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ecosystem:1"},
							},
						},
					},
				}}},
			expected: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-0001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
		},
		{
			name: "args' vulnerability is empty",
			fields: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-0001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
			args: args{
				ds: []dataTypes.Data{{
					ID:              dataTypes.RootID("id"),
					Vulnerabilities: nil,
				}}},
			expected: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-0001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
		},
		{
			name: "different vulnerabilities",
			fields: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-0001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-1001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.2"},
						},
					},
				},
			},
			args: args{
				ds: []dataTypes.Data{{
					ID: dataTypes.RootID("id"),
					Vulnerabilities: []vulnerabilityTypes.Vulnerability{
						{
							Content: vulnerabilityContentTypes.Content{
								ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-2001"),
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ecosystem:2.1"},
							},
						},
						{
							Content: vulnerabilityContentTypes.Content{
								ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-0001"),
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ecosystem:2.2"},
							},
						},
					},
				}}},
			expected: dataTypes.Data{
				ID: dataTypes.RootID("id"),
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-0001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
							{Ecosystem: "ecosystem:2.2"},
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-1001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.2"},
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: vulnerabilityContentTypes.VulnerabilityID("CVE-2024-2001"),
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:2.1"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			(&tt.fields).Merge(tt.args.ds...)
			if diff := cmp.Diff(tt.expected, tt.fields); diff != "" {
				t.Errorf("Merge(). (-expected +got):\n%s", diff)
			}
		})
	}
}
