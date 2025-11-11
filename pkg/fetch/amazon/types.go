package amazon

type catalog struct {
	Topics []struct {
		N            string   `json:"n"`
		Inst         []string `json:"inst,omitempty"`
		Versions     []string `json:"versions"`
		DeprecatedAt string   `json:"deprecated-at,omitempty"`
		Visible      []string `json:"visible,omitempty"`
	} `json:"topics"`
}

type repomd struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
	} `xml:"data"`
}

type updates struct {
	Update []Update `xml:"update"`
}

type Update struct {
	ID      string `xml:"id" json:"ID,omitempty"`
	Author  string `xml:"author,attr" json:"Author,omitempty"`
	From    string `xml:"from,attr" json:"From,omitempty"`
	Status  string `xml:"status,attr" json:"Status,omitempty"`
	Type    string `xml:"type,attr" json:"Type,omitempty"`
	Version string `xml:"version,attr" json:"Version,omitempty"`
	Title   string `xml:"title" json:"Title,omitempty"`
	Issued  struct {
		Date string `xml:"date,attr" json:"Date,omitempty"`
	} `xml:"issued" json:"Issued,omitzero"`
	Updated struct {
		Date string `xml:"date,attr" json:"Date,omitempty"`
	} `xml:"updated" json:"Updated,omitzero"`
	Severity    string `xml:"severity" json:"Severity,omitempty"`
	Description string `xml:"description" json:"Description,omitempty"`
	References  struct {
		Reference []struct {
			Href  string `xml:"href,attr" json:"Href,omitempty"`
			ID    string `xml:"id,attr" json:"ID,omitempty"`
			Title string `xml:"title,attr" json:"Title,omitempty"`
			Type  string `xml:"type,attr" json:"Type,omitempty"`
		} `xml:"reference" json:"Reference,omitempty"`
	} `xml:"references" json:"References,omitzero"`
	Pkglist struct {
		Collection struct {
			Short   string `xml:"short,attr" json:"Short,omitempty"`
			Name    string `xml:"name" json:"Name,omitempty"`
			Package []struct {
				Arch     string `xml:"arch,attr" json:"Arch,omitempty"`
				Epoch    string `xml:"epoch,attr" json:"Epoch,omitempty"`
				Name     string `xml:"name,attr" json:"Name,omitempty"`
				Release  string `xml:"release,attr" json:"Release,omitempty"`
				Version  string `xml:"version,attr" json:"Version,omitempty"`
				Filename string `xml:"filename" json:"Filename,omitempty"`
			} `xml:"package" json:"Package,omitempty"`
		} `xml:"collection" json:"Collection,omitzero"`
	} `xml:"pkglist" json:"Pkglist,omitzero"`
}
