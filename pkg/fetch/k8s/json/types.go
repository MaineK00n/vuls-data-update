package json

type document struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Authors     []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"authors"`
	FeedURL      string `json:"feed_url"`
	HomePageURL  string `json:"home_page_url"`
	KubernetesIo struct {
		FeedRefreshJob string `json:"feed_refresh_job"`
		UpdatedAt      string `json:"updated_at"`
	} `json:"_kubernetes_io"`
	Items []Item `json:"items"`
}

type Item struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Summary      string `json:"summary"`
	ContentText  string `json:"content_text"`
	URL          string `json:"url"`
	ExternalURL  string `json:"external_url"`
	KubernetesIo struct {
		GoogleGroupURL string `json:"google_group_url"`
		IssueNumber    int    `json:"issue_number"`
	} `json:"_kubernetes_io"`
	DatePublished string `json:"date_published"`
}
