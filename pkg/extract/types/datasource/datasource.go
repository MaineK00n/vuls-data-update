package datasource

import (
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

type DataSource struct {
	ID        source.SourceID         `json:"id,omitempty"`
	Name      *string                 `json:"name,omitempty"`
	Raw       []repository.Repository `json:"raw,omitempty"`
	Extracted *repository.Repository  `json:"extracted,omitempty"`
}

func (d *DataSource) Sort() {}
