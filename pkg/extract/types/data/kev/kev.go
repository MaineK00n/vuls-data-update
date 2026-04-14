package kev

import (
	"cmp"
	"time"

	vulncheckTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck"
)

type KEV struct {
	VendorProject              string    `json:"vendor_project,omitempty"`
	Product                    string    `json:"product,omitempty"`
	RequiredAction             string    `json:"required_action,omitempty"`
	KnownRansomwareCampaignUse string    `json:"known_ransomware_campaign_use,omitempty"`
	Notes                      string    `json:"notes,omitempty"`
	DateAdded                  time.Time `json:"date_added,omitzero"`
	DueDate                    time.Time `json:"due_date,omitzero"`

	VulnCheck *vulncheckTypes.VulnCheck `json:"vulncheck,omitempty"`
}

func (k *KEV) Sort() {
	if k.VulnCheck != nil {
		k.VulnCheck.Sort()
	}
}

func Compare(x, y KEV) int {
	return cmp.Or(
		cmp.Compare(x.VendorProject, y.VendorProject),
		cmp.Compare(x.Product, y.Product),
		cmp.Compare(x.RequiredAction, y.RequiredAction),
		cmp.Compare(x.KnownRansomwareCampaignUse, y.KnownRansomwareCampaignUse),
		cmp.Compare(x.Notes, y.Notes),
		x.DateAdded.Compare(y.DateAdded),
		x.DueDate.Compare(y.DueDate),
		func() int {
			switch {
			case x.VulnCheck == nil && y.VulnCheck == nil:
				return 0
			case x.VulnCheck == nil && y.VulnCheck != nil:
				return -1
			case x.VulnCheck != nil && y.VulnCheck == nil:
				return +1
			default:
				return vulncheckTypes.Compare(*x.VulnCheck, *y.VulnCheck)
			}
		}(),
	)
}
