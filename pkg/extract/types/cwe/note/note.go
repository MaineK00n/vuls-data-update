package note

import "cmp"

type Note struct {
	Type        string `json:"type,omitempty"`
	Text        string `json:"text,omitempty"`
	Version     string `json:"version,omitempty"`      // CWE version the note was added in (CWE 5.0)
	ReleaseDate string `json:"release_date,omitempty"` // release date of that version (CWE 5.0)
}

func Compare(x, y Note) int {
	return cmp.Or(
		cmp.Compare(x.Type, y.Type),
		cmp.Compare(x.Text, y.Text),
		cmp.Compare(x.Version, y.Version),
		cmp.Compare(x.ReleaseDate, y.ReleaseDate),
	)
}
