package bottlerocket

import "encoding/xml"

type updates struct {
	XMLName xml.Name `xml:"updates" json:"updates,omitempty"`
	Update  []Update `xml:"update" json:"update,omitempty"`
}

type Update struct {
	Author  string `xml:"author,attr" json:"author,omitempty"`
	From    string `xml:"from,attr" json:"from,omitempty"`
	Status  string `xml:"status,attr" json:"status,omitempty"`
	Type    string `xml:"type,attr" json:"type,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	ID      string `xml:"id"`
	Title   string `xml:"title"`
	Issued  struct {
		Date string `xml:"date,attr" json:"date,omitempty"`
	} `xml:"issued" json:"issued,omitempty"`
	Updated struct {
		Date string `xml:"date,attr" json:"date,omitempty"`
	} `xml:"updated" json:"updated,omitempty"`
	Severity    string `xml:"severity"`
	Description string `xml:"description"`
	References  struct {
		Reference []struct {
			Href string `xml:"href,attr" json:"href,omitempty"`
			ID   string `xml:"id,attr" json:"id,omitempty"`
			Type string `xml:"type,attr" json:"type,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
	} `xml:"references" json:"references,omitempty"`
	Pkglist struct {
		Collection struct {
			Short   string `xml:"short,attr" json:"short,omitempty"`
			Name    string `xml:"name"`
			Package []struct {
				Arch    string `xml:"arch,attr" json:"arch,omitempty"`
				Name    string `xml:"name,attr" json:"name,omitempty"`
				Version string `xml:"version,attr" json:"version,omitempty"`
				Release string `xml:"release,attr" json:"release,omitempty"`
				Epoch   string `xml:"epoch,attr" json:"epoch,omitempty"`
			} `xml:"package" json:"package,omitempty"`
		} `xml:"collection" json:"collection,omitempty"`
	} `xml:"pkglist" json:"pkglist,omitempty"`
}
