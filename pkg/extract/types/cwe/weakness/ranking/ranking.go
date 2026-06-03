package ranking

import "cmp"

// Ranking records that a weakness appears in a CWE ranking list at a given
// position, attached to each ranked weakness so the rank is visible from the
// weakness entry itself. It is derived from two list shapes, which differ in
// the fields they populate:
//   - "CWE Top 25" and "CWE/SANS Top 25" views: ViewID, ViewName, Rank and
//     Score, all from supplemental data; no Category.
//   - OWASP Top Ten views: ViewID, ViewName, the A-tier CategoryID/CategoryName,
//     and Rank (the "A0N" number shared by the category's weaknesses); no Score.
type Ranking struct {
	ViewID       string  `json:"view_id,omitempty"`       // ranking list view, e.g. "CWE-1430" / "CWE-1344"
	ViewName     string  `json:"view_name,omitempty"`     // e.g. "Weaknesses in OWASP Top Ten (2021)"
	CategoryID   string  `json:"category_id,omitempty"`   // OWASP only: the A-tier category, e.g. "CWE-1347"
	CategoryName string  `json:"category_name,omitempty"` // OWASP only: e.g. "OWASP Top Ten 2021 Category A03:2021 - Injection"
	Rank         int     `json:"rank,omitzero"`           // 1-based position in the list
	Score        float64 `json:"score,omitzero"`          // published score where one exists (CWE Top 25, CWE/SANS)
}

func Compare(x, y Ranking) int {
	return cmp.Or(
		cmp.Compare(x.ViewID, y.ViewID),
		cmp.Compare(x.ViewName, y.ViewName),
		cmp.Compare(x.CategoryID, y.CategoryID),
		cmp.Compare(x.CategoryName, y.CategoryName),
		cmp.Compare(x.Rank, y.Rank),
		cmp.Compare(x.Score, y.Score),
	)
}
