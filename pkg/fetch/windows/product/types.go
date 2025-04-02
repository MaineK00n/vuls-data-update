package product

import "time"

type response struct {
	OdataContext  string    `json:"@odata.context"`
	OdataCount    int       `json:"@odata.count"`
	Value         []Product `json:"value"`
	OdataNextLink string    `json:"@odata.nextLink"`
}

type Product struct {
	ID                     string  `json:"id"`
	Architecture           *string `json:"architecture,omitempty"`
	ArchitectureID         int     `json:"architectureId"`
	BaseProductName        *string `json:"baseProductName,omitempty"`
	BaseProductVersion     *string `json:"baseProductVersion,omitempty"`
	BaseScore              *string `json:"baseScore,omitempty"`
	Cpe                    *string `json:"cpe,omitempty"`
	CustomerActionRequired bool    `json:"customerActionRequired"`
	CveNumber              string  `json:"cveNumber"`
	CweDetailsList         []struct {
		Keys   []string `json:"keys"`
		Values []string `json:"values"`
	} `json:"cweDetailsList"`
	CweList            []string  `json:"cweList"`
	EnvironmentalScore *string   `json:"environmentalScore,omitempty"`
	Impact             *string   `json:"impact,omitempty"`
	ImpactID           int       `json:"impactId"`
	InitialReleaseDate time.Time `json:"initialReleaseDate"`
	IsMariner          bool      `json:"isMariner"`
	IssuingCna         *string   `json:"issuingCna,omitempty"`
	KbArticles         []struct {
		AffectedBinaries []string `json:"affectedBinaries"`
		ArticleName      *string  `json:"articleName,omitempty"`
		ArticleURL       *string  `json:"articleUrl,omitempty"`
		DownloadName     string   `json:"downloadName"`
		DownloadURL      *string  `json:"downloadUrl,omitempty"`
		FixedBuildNumber *string  `json:"fixedBuildNumber,omitempty"`
		KnownIssuesName  *string  `json:"knownIssuesName,omitempty"`
		KnownIssuesURL   *string  `json:"knownIssuesUrl,omitempty"`
		Ordinal          int      `json:"ordinal"`
		RebootRequired   *string  `json:"rebootRequired,omitempty"`
		Supercedence     *string  `json:"supercedence,omitempty"`
	} `json:"kbArticles"`
	Platform        *string   `json:"platform,omitempty"`
	PlatformID      int       `json:"platformId"`
	Product         string    `json:"product"`
	ProductFamily   string    `json:"productFamily"`
	ProductFamilyID int       `json:"productFamilyId"`
	ProductID       int       `json:"productId"`
	ProductVersion  *string   `json:"productVersion,omitempty"`
	ReleaseDate     time.Time `json:"releaseDate"`
	ReleaseNumber   *string   `json:"releaseNumber,omitempty"`
	Severity        *string   `json:"severity,omitempty"`
	SeverityID      int       `json:"severityId"`
	TemporalScore   *string   `json:"temporalScore,omitempty"`
	VectorString    *string   `json:"vectorString,omitempty"`
}
