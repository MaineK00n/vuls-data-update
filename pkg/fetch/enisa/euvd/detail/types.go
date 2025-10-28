package detail

type Advisory struct {
	ID                   string    `json:"id"`
	EnisaUUID            string    `json:"enisaUuid"`
	Description          string    `json:"description"`
	DatePublished        string    `json:"datePublished"`
	DateUpdated          string    `json:"dateUpdated"`
	BaseScore            float64   `json:"baseScore"`
	BaseScoreVersion     string    `json:"baseScoreVersion"`
	BaseScoreVector      string    `json:"baseScoreVector"`
	References           string    `json:"references"`
	Aliases              string    `json:"aliases"`
	Assigner             string    `json:"assigner"`
	EPSS                 float64   `json:"epss"`
	EnisaIDProduct       []Product `json:"enisaIdProduct"`
	EnisaIDVendor        []Vendor  `json:"enisaIdVendor"`
	EnisaIDVulnerability []struct {
		ID            string `json:"id"`
		Vulnerability struct {
			ID                   string    `json:"id"`
			Description          *string   `json:"description,omitempty"`
			DatePublished        string    `json:"datePublished"`
			DateUpdated          string    `json:"dateUpdated"`
			Status               *string   `json:"status,omitempty"`
			BaseScore            float64   `json:"baseScore"`
			BaseScoreVersion     *string   `json:"baseScoreVersion,omitempty"`
			BaseScoreVector      *string   `json:"baseScoreVector,omitempty"`
			References           string    `json:"references"`
			EnisaID              string    `json:"enisa_id"`
			Aliases              *string   `json:"aliases,omitempty"`
			Assigner             *string   `json:"assigner,omitempty"`
			EPSS                 float64   `json:"epss"`
			DataProcessed        string    `json:"dataProcessed"`
			VulnerabilityProduct []Product `json:"vulnerabilityProduct"`
			VulnerabilityVendor  []Vendor  `json:"vulnerabilityVendor"`
		} `json:"vulnerability"`
	} `json:"enisaIdVulnerability"`
	EnisaIDAdvisory []struct {
		ID       string `json:"id"`
		Advisory struct {
			ID            string  `json:"id"`
			Description   string  `json:"description"`
			Summary       *string `json:"summary,omitempty"`
			DatePublished string  `json:"datePublished"`
			DateUpdated   string  `json:"dateUpdated"`
			BaseScore     int     `json:"baseScore"`
			References    string  `json:"references"`
			Aliases       string  `json:"aliases"`
			Source        struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"source"`
			AdvisoryProduct []Product `json:"advisoryProduct"`
		} `json:"advisory"`
	} `json:"enisaIdAdvisory"`
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
