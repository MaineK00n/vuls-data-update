package update

import (
	"testing"
	"time"

	supersededbyTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/microsoftkb/supersededby"
)

func TestUpdate_Sort(t *testing.T) {
	type fields struct {
		UpdateID           string
		Title              string
		Description        string
		SecurityBulletin   string
		MSRCSeverity       string
		Architecture       string
		Classification     string
		ProductFamily      string
		Products           []string
		Languages          []string
		MoreInfoURL        string
		SupportURL         string
		SupersededBy       []supersededbyTypes.SupersededBy
		RebootBehavior     string
		UserInput          string
		InstallationImpact string
		Connectivity       string
		UninstallNotes     string
		UninstallSteps     string
		CreationDate       time.Time
		LastModified       time.Time
		CatalogURL         string
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Update{
				UpdateID:           tt.fields.UpdateID,
				Title:              tt.fields.Title,
				Description:        tt.fields.Description,
				SecurityBulletin:   tt.fields.SecurityBulletin,
				MSRCSeverity:       tt.fields.MSRCSeverity,
				Architecture:       tt.fields.Architecture,
				Classification:     tt.fields.Classification,
				ProductFamily:      tt.fields.ProductFamily,
				Products:           tt.fields.Products,
				Languages:          tt.fields.Languages,
				MoreInfoURL:        tt.fields.MoreInfoURL,
				SupportURL:         tt.fields.SupportURL,
				SupersededBy:       tt.fields.SupersededBy,
				RebootBehavior:     tt.fields.RebootBehavior,
				UserInput:          tt.fields.UserInput,
				InstallationImpact: tt.fields.InstallationImpact,
				Connectivity:       tt.fields.Connectivity,
				UninstallNotes:     tt.fields.UninstallNotes,
				UninstallSteps:     tt.fields.UninstallSteps,
				CreationDate:       tt.fields.CreationDate,
				LastModified:       tt.fields.LastModified,
				CatalogURL:         tt.fields.CatalogURL,
			}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x Update
		y Update
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
			if got := Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
