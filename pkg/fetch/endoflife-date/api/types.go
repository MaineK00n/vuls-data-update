package api

// https://endoflife.date/docs/api/v1/#/Products/products_full
type response struct {
	SchemaVersion string    `json:"schema_version"`
	Total         int       `json:"total"`
	GeneratedAt   string    `json:"generated_at"`
	Result        []Product `json:"result"`
}

type Product struct {
	Name           string   `json:"name"`
	Label          string   `json:"label"`
	Aliases        []string `json:"aliases"`
	Category       string   `json:"category"`
	Tags           []string `json:"tags"`
	VersionCommand *string  `json:"versionCommand,omitempty"`
	Identifiers    []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"identifiers"`
	Labels struct {
		EOAS         *string `json:"eoas,omitempty"`
		Discontinued *string `json:"discontinued,omitempty"`
		EOL          string  `json:"eol"`
		EOES         *string `json:"eoes,omitempty"`
	} `json:"labels"`
	Links struct {
		Icon          *string `json:"icon,omitempty"`
		HTML          string  `json:"html"`
		ReleasePolicy *string `json:"releasePolicy,omitempty"`
	} `json:"links"`
	Releases []struct {
		Name             string  `json:"name"`
		Codename         *string `json:"codename"`
		Label            string  `json:"label"`
		ReleaseDate      string  `json:"releaseDate"`
		IsLTS            bool    `json:"isLts"`
		LTSFrom          *string `json:"ltsFrom,omitempty"`
		IsEOAS           *bool   `json:"isEoas,omitempty"`
		EOASFrom         *string `json:"eoasFrom,omitempty"`
		IsEOL            bool    `json:"isEol"`
		EOLFrom          *string `json:"eolFrom,omitempty"`
		IsDiscontinued   bool    `json:"isDiscontinued"`
		DiscontinuedFrom *string `json:"discontinuedFrom,omitempty"`
		IsEOES           *bool   `json:"isEoes,omitempty"`
		EOESFrom         *string `json:"eoesFrom,omitempty"`
		IsMaintained     bool    `json:"isMaintained"`
		Latest           *struct {
			Name string  `json:"name"`
			Date *string `json:"date"`
			Link *string `json:"link"`
		} `json:"latest,omitempty"`
		Custom map[string]*string `json:"custom,omitempty"`
	} `json:"releases"`
}
