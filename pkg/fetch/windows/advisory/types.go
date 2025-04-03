package advisory

import "time"

type response struct {
	OdataContext  string     `json:"@odata.context"`
	OdataCount    int        `json:"@odata.count"`
	Value         []Advisory `json:"value"`
	OdataNextLink string     `json:"@odata.nextLink"`
}

type Advisory struct {
	ID             string    `json:"id"`
	AdvisoryNumber string    `json:"advisoryNumber"`
	AdvisoryType   string    `json:"advisoryType"`
	Body           string    `json:"body"`
	CreatedOn      time.Time `json:"createdOn"`
	IsRemoved      bool      `json:"isRemoved"`
	LangCode       string    `json:"langCode"`
	ModifiedOn     time.Time `json:"modifiedOn"`
	PublishDate    time.Time `json:"publishDate"`
	Title          string    `json:"title"`
	Version        float64   `json:"version"`
}
