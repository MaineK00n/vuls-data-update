package api

import (
	"testing"

	fetchapi "github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora/api"
)

func TestExtractSkipsEmptyDetections(t *testing.T) {
	tests := []struct {
		name           string
		builds         []fetchapi.Build
		wantDetections int
	}{
		{
			name: "no builds",
		},
		{
			name: "flatpak only",
			builds: []fetchapi.Build{{
				Type: "flatpak",
			}},
		},
		{
			name: "container only",
			builds: []fetchapi.Build{{
				Type: "container",
			}},
		},
		{
			name: "rpm and flatpak",
			builds: []fetchapi.Build{
				{
					Type: "rpm",
					Package: map[string][]fetchapi.Package{
						"x86_64": []fetchapi.Package{{
							Name:    "bash",
							Version: "1.0.0",
							Release: "1.fc32",
							Arch:    "x86_64",
						}},
					},
				},
				{
					Type: "flatpak",
				},
			},
			wantDetections: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetched := fetchapi.Advisory{
				Builds:        tt.builds,
				DateSubmitted: "2021-01-02 03:04:05",
				Updateid:      "FEDORA-2021-example",
			}
			fetched.Release.IDPrefix = "FEDORA"
			fetched.Release.Version = "32"

			got, err := extract(fetched, []string{"raw.json"})
			if err != nil {
				t.Fatalf("extract() error = %v", err)
			}
			if got == nil {
				t.Fatal("extract() returned nil data")
			}
			if len(got.Advisories) != 1 {
				t.Fatalf("len(got.Advisories) = %d, want 1", len(got.Advisories))
			}
			if len(got.Detections) != tt.wantDetections {
				t.Fatalf("len(got.Detections) = %d, want %d", len(got.Detections), tt.wantDetections)
			}
			if tt.wantDetections > 0 && len(got.Detections[0].Conditions[0].Criteria.Criterions) == 0 {
				t.Fatal("got detection with no criterions")
			}
		})
	}
}
