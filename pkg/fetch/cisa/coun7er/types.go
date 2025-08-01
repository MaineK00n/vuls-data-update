package coun7er

type doc struct {
	ID          string      `json:"id"`
	Version     string      `json:"version"`
	Name        string      `json:"name"`
	URL         interface{} `json:"url"`
	SpecVersion string      `json:"spec_version"`
	ItemType    string      `json:"item_type"`
	Items       []Item      `json:"items"`
	Templates   []Template  `json:"templates"`
}

type Item struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Subtype       *string       `json:"subtype"`
	URL           interface{}   `json:"url"`
	Content       string        `json:"content"`
	Version       string        `json:"version"`
	Created       string        `json:"created"`
	Modified      string        `json:"modified"`
	Contributors  []interface{} `json:"contributors"`
	Technologies  []interface{} `json:"technologies"`
	Platforms     []interface{} `json:"platforms"`
	Revoked       interface{}   `json:"revoked"`
	Deprecated    interface{}   `json:"deprecated"`
	IDsBeforeThis []interface{} `json:"ids_before_this"`
	IDsAfterThis  []interface{} `json:"ids_after_this"`
	IsBaseline    bool          `json:"is_baseline"`
	RelatedIDs    []string      `json:"related_ids"`
	Automatable   string        `json:"automatable"`
	References    []struct {
		Description string `json:"description"`
		SourceName  string `json:"source_name"`
		URL         string `json:"url"`
	} `json:"references"`
	Techniques []struct {
		TechID  string      `json:"tech_id"`
		Content interface{} `json:"content"`
		Details interface{} `json:"details"`
	} `json:"techniques"`
}

type Template struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Featured bool        `json:"featured"`
	IconSrc  interface{} `json:"iconSrc"`
	Link     *struct {
		Text string `json:"text"`
		URL  string `json:"url"`
	} `json:"link"`
	Description string `json:"description"`
	TechToItems map[string]struct {
		Confidence string `json:"confidence"`
		Items      []struct {
			ID      string `json:"id"`
			Version string `json:"version"`
		} `json:"items"`
	} `json:"tech_to_items"`
	IgnoredItems []interface{} `json:"ignored_items"`
}
