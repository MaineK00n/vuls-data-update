package datasource_test

import (
	"testing"

	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

func TestDataSource_Sort(t *testing.T) {
	type fields struct {
		ID        sourceTypes.SourceID
		Name      *string
		Raw       []repositoryTypes.Repository
		Extracted *repositoryTypes.Repository
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &datasourceTypes.DataSource{
				ID:        tt.fields.ID,
				Name:      tt.fields.Name,
				Raw:       tt.fields.Raw,
				Extracted: tt.fields.Extracted,
			}
			d.Sort()
		})
	}
}
