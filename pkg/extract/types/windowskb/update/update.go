package update

import (
	"cmp"
	"slices"
	"time"

	supersededbyTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb/supersededby"
)

// Update represents a specific update instance identified by Update ID (UUID).
// A single KB may have multiple updates for different architectures/products.
type Update struct {
	UpdateID           string                           `json:"update_id"`
	Title              string                           `json:"title,omitempty"`
	Description        string                           `json:"description,omitempty"`
	SecurityBulletin   string                           `json:"security_bulletin,omitempty"`
	MSRCSeverity       string                           `json:"msrc_severity,omitempty"`
	Architecture       string                           `json:"architecture,omitempty"`
	Classification     string                           `json:"classification,omitempty"`
	ProductFamily      string                           `json:"product_family,omitempty"`
	Products           []string                         `json:"products,omitempty"`
	Languages          []string                         `json:"languages,omitempty"`
	MoreInfoURL        string                           `json:"more_info_url,omitempty"`
	SupportURL         string                           `json:"support_url,omitempty"`
	SupersededBy       []supersededbyTypes.SupersededBy `json:"superseded_by,omitempty"`
	RebootBehavior     string                           `json:"reboot_behavior,omitempty"`
	UserInput          string                           `json:"user_input,omitempty"`
	InstallationImpact string                           `json:"installation_impact,omitempty"`
	Connectivity       string                           `json:"connectivity,omitempty"`
	UninstallNotes     string                           `json:"uninstall_notes,omitempty"`
	UninstallSteps     string                           `json:"uninstall_steps,omitempty"`
	CreationDate       time.Time                        `json:"creation_date"`
	LastModified       time.Time                        `json:"last_modified"`
	CatalogURL         string                           `json:"catalog_url"`
}

func (d *Update) Sort() {
	slices.Sort(d.Products)
	slices.Sort(d.Languages)

	for i := range d.SupersededBy {
		d.SupersededBy[i].Sort()
	}
	slices.SortFunc(d.SupersededBy, supersededbyTypes.Compare)
}

func Compare(x, y Update) int {
	return cmp.Or(
		cmp.Compare(x.UpdateID, y.UpdateID),
		cmp.Compare(x.Title, y.Title),
		cmp.Compare(x.Description, y.Description),
		cmp.Compare(x.SecurityBulletin, y.SecurityBulletin),
		cmp.Compare(x.MSRCSeverity, y.MSRCSeverity),
		cmp.Compare(x.Architecture, y.Architecture),
		cmp.Compare(x.Classification, y.Classification),
		cmp.Compare(x.ProductFamily, y.ProductFamily),
		slices.Compare(x.Products, y.Products),
		slices.Compare(x.Languages, y.Languages),
		cmp.Compare(x.MoreInfoURL, y.MoreInfoURL),
		cmp.Compare(x.SupportURL, y.SupportURL),
		slices.CompareFunc(x.SupersededBy, y.SupersededBy, supersededbyTypes.Compare),
		cmp.Compare(x.RebootBehavior, y.RebootBehavior),
		cmp.Compare(x.UserInput, y.UserInput),
		cmp.Compare(x.InstallationImpact, y.InstallationImpact),
		cmp.Compare(x.Connectivity, y.Connectivity),
		cmp.Compare(x.UninstallNotes, y.UninstallNotes),
		cmp.Compare(x.UninstallSteps, y.UninstallSteps),
		x.CreationDate.Compare(y.CreationDate),
		x.LastModified.Compare(y.LastModified),
		cmp.Compare(x.CatalogURL, y.CatalogURL),
	)
}
