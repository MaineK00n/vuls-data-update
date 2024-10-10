package data_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
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
		{
			name: "merge advisories",
			fields: dataTypes.Data{
				ID: "id",
				Advisories: []advisoryTypes.Advisory{
					{
						Content: advisoryContentTypes.Content{
							ID: "advisory-duplicated",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-1",
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: "advisory-only-in-1",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-2",
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
									ID: "advisory-only-in-2",
								},
								Ecosystems: []ecosystemTypes.Ecosystem{
									"ecosystem2-1",
								},
							},
							{
								Content: advisoryContentTypes.Content{
									ID: "advisory-duplicated",
								},
								Ecosystems: []ecosystemTypes.Ecosystem{
									"ecosystem2-2",
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
							ID: "advisory-duplicated",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-1",
							"ecosystem2-2",
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: "advisory-only-in-1",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-2",
						},
					},
					{
						Content: advisoryContentTypes.Content{
							ID: "advisory-only-in-2",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem2-1",
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
							ID: "vulnerability-duplicated",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-1",
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "vulnerability-only-in-1",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-2",
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
								ID: "vulnerability-only-in-2",
							},
							Ecosystems: []ecosystemTypes.Ecosystem{
								"ecosystem2-1",
							},
						},
						{
							Content: vulnerabilityContentTypes.Content{
								ID: "vulnerability-duplicated",
							},
							Ecosystems: []ecosystemTypes.Ecosystem{
								"ecosystem2-2",
							},
						},
					},
				}}},
			expected: dataTypes.Data{
				ID: "id",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "vulnerability-duplicated",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-1",
							"ecosystem2-2",
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "vulnerability-only-in-1",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem1-2",
						},
					},
					{
						Content: vulnerabilityContentTypes.Content{
							ID: "vulnerability-only-in-2",
						},
						Ecosystems: []ecosystemTypes.Ecosystem{
							"ecosystem2-1",
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
