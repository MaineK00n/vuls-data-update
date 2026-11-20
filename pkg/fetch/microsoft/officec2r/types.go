package officec2r

// Release is one dated entry of "Release notes for Microsoft 365 Apps security
// updates", stored as the page states it.
type Release struct {
	// ID is the id attribute of the entry heading (e.g. "october-13-2026").
	ID string `json:"id"`
	// Date is the heading text as published (e.g. "October 13, 2026", "October 08, 2024").
	Date string `json:"date"`
	// Builds lists the "<Channel>: Version <Version> (Build <Build>)" lines of the
	// entry, in page order. A channel may appear on several lines, one per version.
	Builds []Build `json:"builds,omitempty"`
	// Description holds the entry paragraph when it states something other than
	// builds (e.g. "There are no security updates for any channel this month.").
	Description string `json:"description,omitempty"`
	// Sections are the per-application lists (e.g. "Excel", "Office suite"), in page order.
	Sections []Section `json:"sections,omitempty"`
}

type Build struct {
	// Channel is the text before ": Version" (e.g. "Monthly Enterprise Channel",
	// "Office LTSC 2021 Volume Licensed").
	Channel string `json:"channel"`
	// Version is the four-digit version (e.g. "2609").
	Version string `json:"version"`
	// Build is the build number without the "16.0." prefix (e.g. "20430.20182").
	Build string `json:"build"`
	// Note is text following the build number inside the parentheses
	// (e.g. "rolled back", "released August 18, 2022").
	Note string `json:"note,omitempty"`
}

type Section struct {
	Name  string `json:"name"`
	Items []Item `json:"items,omitempty"`
}

type Item struct {
	// Text is the whole list item text, whitespace collapsed.
	Text  string `json:"text"`
	Links []Link `json:"links,omitempty"`
}

type Link struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}
