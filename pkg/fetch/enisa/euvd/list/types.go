package list

type response struct {
	Items []Item `json:"items"`
	Total int    `json:"total"`
}

type Item struct {
	ID               string    `json:"id"`
	EnisaUUID        string    `json:"enisaUuid"`
	Description      string    `json:"description"`
	DatePublished    string    `json:"datePublished"`
	DateUpdated      string    `json:"dateUpdated"`
	BaseScore        float64   `json:"baseScore"`
	BaseScoreVersion string    `json:"baseScoreVersion"`
	BaseScoreVector  string    `json:"baseScoreVector"`
	References       string    `json:"references"`
	Aliases          string    `json:"aliases"`
	Assigner         string    `json:"assigner"`
	EPSS             float64   `json:"epss"`
	EnisaIDProduct   []Product `json:"enisaIdProduct"`
	EnisaIDVendor    []Vendor  `json:"enisaIdVendor"`
}

type Product struct {
	ID      string `json:"id"`
	Product struct {
		Name string `json:"name"`
	} `json:"product"`
	ProductVersion string `json:"product_version,omitempty"`
}

type Vendor struct {
	ID     string `json:"id"`
	Vendor struct {
		Name string `json:"name"`
	} `json:"vendor"`
}
