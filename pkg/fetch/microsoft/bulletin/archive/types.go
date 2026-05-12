package archive

// Archive holds the raw markdown for a single Microsoft Security Bulletin
// archive page on Microsoft Learn.
type Archive struct {
	ID       string `json:"id"`
	Year     string `json:"year"`
	URL      string `json:"url"`
	Markdown string `json:"markdown"`
}
