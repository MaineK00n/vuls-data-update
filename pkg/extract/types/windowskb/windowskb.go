package windowskb

import (
	"cmp"
	"slices"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	windowskbSupersededByTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb/supersededby"
	windowskbUpdateTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb/update"
)

// KB represents a Microsoft Knowledge Base article as a grouping key.
// SupersededBy at this level holds KB-level supersession info (e.g. from CVRF).
// Per-update supersession is stored in each Update's SupersededBy.
type KB struct {
	KBID         string                                    `json:"kb_id"`
	Products     []string                                  `json:"products,omitempty"`
	SupersededBy []windowskbSupersededByTypes.SupersededBy `json:"superseded_by,omitempty"`
	Updates      []windowskbUpdateTypes.Update             `json:"updates,omitempty"`
	DataSource   sourceTypes.Source                        `json:"data_source,omitzero"`
}

func (d *KB) Sort() {
	slices.Sort(d.Products)

	for i := range d.SupersededBy {
		d.SupersededBy[i].Sort()
	}
	slices.SortFunc(d.SupersededBy, windowskbSupersededByTypes.Compare)

	for i := range d.Updates {
		d.Updates[i].Sort()
	}
	slices.SortFunc(d.Updates, windowskbUpdateTypes.Compare)

	d.DataSource.Sort()
}

func Compare(x, y KB) int {
	return cmp.Or(
		cmp.Compare(x.KBID, y.KBID),
		slices.Compare(x.Products, y.Products),
		slices.CompareFunc(x.SupersededBy, y.SupersededBy, windowskbSupersededByTypes.Compare),
		slices.CompareFunc(x.Updates, y.Updates, windowskbUpdateTypes.Compare),
		sourceTypes.Compare(x.DataSource, y.DataSource),
	)
}

func (d *KB) Merge(kbs ...KB) {
	for _, e := range kbs {
		if d.KBID != e.KBID {
			continue
		}

		ps := d.Products
		for _, ep := range e.Products {
			if !slices.Contains(ps, ep) {
				ps = append(ps, ep)
			}
		}
		d.Products = ps

		ss := d.SupersededBy
		for _, es := range e.SupersededBy {
			if !slices.ContainsFunc(ss, func(s windowskbSupersededByTypes.SupersededBy) bool {
				return windowskbSupersededByTypes.Compare(s, es) == 0
			}) {
				ss = append(ss, es)
			}
		}
		d.SupersededBy = ss

		us := d.Updates
		for _, eu := range e.Updates {
			if !slices.ContainsFunc(us, func(u windowskbUpdateTypes.Update) bool {
				return windowskbUpdateTypes.Compare(u, eu) == 0
			}) {
				us = append(us, eu)
			}
		}
		d.Updates = us

		for _, r := range e.DataSource.Raws {
			if !slices.Contains(d.DataSource.Raws, r) {
				d.DataSource.Raws = append(d.DataSource.Raws, r)
			}
		}
	}
}
