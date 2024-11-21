package data_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
)

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
				ID:         "id",
				Advisories: nil,
			},
			args: args{
				ds: []dataTypes.Data{
					{
						ID: "id",
						Advisories: []advisoryTypes.Advisory{
							{
								Content: advisoryContentTypes.Content{
									ID: "ADV-001",
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
				ID: "id",
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-001",
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
				ID: "id",
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-001",
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
						ID:         "id",
						Advisories: nil,
					},
				},
			},
			expected: dataTypes.Data{
				ID: "id",
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-001",
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
				ID: "id",
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-001",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-101",
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
						ID: "id",
						Advisories: []advisoryTypes.Advisory{
							{
								Content: advisoryContentTypes.Content{
									ID: "ADV-201",
								},
								Segments: []segmentTypes.Segment{
									{Ecosystem: "ecosystem:2.1"},
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "ADV-001",
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
				ID: "id",
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-001",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
							{Ecosystem: "ecosystem:2.2"},
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-101",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.2"},
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: "ADV-201",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:2.1"},
						},
					},
				},
			},
		},
		// cases to merge vulnerablities
		{
			name: "receiver's vulnerability is empty",
			fields: dataTypes.Data{
				ID:              "id",
				Vulnerabilities: nil,
			},
			args: args{
				ds: []dataTypes.Data{{
					ID: "id",
					Vulnerabilities: []vulnerabilityTypes.Vulnerability{
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "CVE-2024-0001",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ecosystem:1"},
							},
						},
					},
				}}},
			expected: dataTypes.Data{
				ID: "id",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-0001",
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
				ID: "id",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-0001",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1"},
						},
					},
				},
			},
			args: args{
				ds: []dataTypes.Data{{
					ID:              "id",
					Vulnerabilities: nil,
				}}},
			expected: dataTypes.Data{
				ID: "id",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-0001",
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
				ID: "id",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-0001",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-1001",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.2"},
						},
					},
				},
			},
			args: args{
				ds: []dataTypes.Data{{
					ID: "id",
					Vulnerabilities: []vulnerabilityTypes.Vulnerability{
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "CVE-2024-2001",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ecosystem:2.1"},
							},
						},
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "CVE-2024-0001",
							},
							Segments: []segmentTypes.Segment{
								{Ecosystem: "ecosystem:2.2"},
							},
						},
					},
				}}},
			expected: dataTypes.Data{
				ID: "id",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-0001",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.1"},
							{Ecosystem: "ecosystem:2.2"},
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-1001",
						},
						Segments: []segmentTypes.Segment{
							{Ecosystem: "ecosystem:1.2"},
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "CVE-2024-2001",
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
				t.Errorf("Fetch(). (-expected +got):\n%s", diff)
			}
		})
	}
}
