package deployment

import "time"

type response struct {
	OdataContext  string       `json:"@odata.context"`
	OdataCount    int          `json:"@odata.count"`
	Value         []Deployment `json:"value"`
	OdataNextLink string       `json:"@odata.nextLink"`
}

type Deployment struct {
	ID               string    `json:"id"`
	ArticleName      *string   `json:"articleName,omitempty"`
	ArticleURL       *string   `json:"articleUrl,omitempty"`
	DownloadName     string    `json:"downloadName"`
	DownloadURL      *string   `json:"downloadUrl,omitempty"`
	FixedBuildNumber *string   `json:"fixedBuildNumber,omitempty"`
	Impact           *string   `json:"impact,omitempty"`
	ImpactID         int       `json:"impactId"`
	KnownIssuesName  *string   `json:"knownIssuesName,omitempty"`
	KnownIssuesURL   *string   `json:"knownIssuesUrl,omitempty"`
	Ordinal          int       `json:"ordinal"`
	Platform         *string   `json:"platform,omitempty"`
	PlatformID       int       `json:"platformId"`
	Product          string    `json:"product"`
	ProductFamily    string    `json:"productFamily"`
	ProductFamilyID  int       `json:"productFamilyId"`
	ProductID        int       `json:"productId"`
	RebootRequired   *string   `json:"rebootRequired,omitempty"`
	ReleaseDate      time.Time `json:"releaseDate"`
	ReleaseNumber    string    `json:"releaseNumber"`
	Severity         *string   `json:"severity,omitempty"`
	SeverityID       int       `json:"severityId"`
	Supercedence     *string   `json:"supercedence,omitempty"`
}
