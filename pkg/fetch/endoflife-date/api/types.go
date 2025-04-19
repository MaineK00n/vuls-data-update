package api

// https://endoflife.date/docs/api
type Cycle struct {
	Cycle        any     `json:"cycle"`          // number or string
	ReleaseDate  string  `json:"releaseDate"`    // string<date>
	EOL          any     `json:"eol"`            // string or boolean
	Latest       string  `json:"latest"`         // string
	Link         *string `json:"link,omitempty"` // string or null
	LTS          any     `json:"lts"`            // string or boolean
	Support      any     `json:"support"`        // string<date> or boolean
	Discontinued any     `json:"discontinued"`   // string<date> or boolean
}
