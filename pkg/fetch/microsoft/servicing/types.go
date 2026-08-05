package servicing

// Article is one servicing article, as served.
//
// The series an article belongs to is its position in the tree, not a field:
// every article of a series is stored, so listing the directory reconstructs
// the membership that Microsoft renders as a sidebar on each page. Storing that
// sidebar as well would repeat one ~225-entry list across the ~300 articles of
// os/windows-11, and rewrite all of them each time a new update ships.
//
// Nothing is parsed out of Title. It is the only place several facts appear —
// "Preview", "Out-of-band", "(Monthly Rollup)", "(Security-only update)" name
// servicing tracks that supersede each other differently, and OS articles carry
// their build numbers there — but Microsoft writes it at least four ways, and
// the oldest .NET form has no date at all:
//
//	July 14, 2026—KB5101649 (OS Build 28000.2525)
//	July 14, 2026 — KB5101004 Cumulative Update for .NET Framework 3.5 ...
//	KB5022497 Cumulative Update for .NET Framework 3.5, 4.8.1 for Windows 11 ...
//	February 13, 2024 security update (KB5034769)
//
// Reading those apart belongs in extract, under golden tests, where a fifth
// spelling is handled by rerunning against origin/ rather than refetching. It
// also keeps articles that name no KB anywhere, such as "MS05-001:
// Vulnerability in HTML Help could allow code execution", from being dropped
// for want of a key.
type Article struct {
	// URL is the article's own canonical link, taken from the stored page rather
	// than from the request, so raw/ stays derivable from origin/ alone.
	URL   string `json:"url,omitempty"`
	Title string `json:"title"`
}
