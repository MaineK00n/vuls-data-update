package kev

import (
	"cmp"
	"time"
)

type KEV struct {
	VendorProject              string    `json:"vendorProject,omitempty"`
	Product                    string    `json:"product,omitempty"`
	RequiredAction             string    `json:"requiredAction,omitempty"`
	KnownRansomwareCampaignUse string    `json:"knownRansomwareCampaignUse,omitempty"`
	Notes                      string    `json:"notes,omitempty"`
	DateAdded                  time.Time `json:"dateAdded,omitempty"`
	DueDate                    time.Time `json:"dueDate,omitempty"`
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
	)
}
