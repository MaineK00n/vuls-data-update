package appstreamlifecycle

type ApplicationStreamTable struct {
	Title              string              `json:"title"`
	Major              string              `json:"major"`
	ApplicationStreams []ApplicationStream `json:"application_streams,omitempty"`
}

type ApplicationStream struct {
	ApplicationStream string `json:"application_stream,omitempty"`
	ReleaseDate       string `json:"release_date,omitempty"`
	RetirementDate    string `json:"retirement_date,omitempty"`
	Release           string `json:"release,omitempty"`
}

type FullLifeApplicationStreamTable struct {
	Title              string                      `json:"title"`
	Major              string                      `json:"major"`
	ApplicationStreams []FullLifeApplicationStream `json:"application_streams,omitempty"`
}

type FullLifeApplicationStream struct {
	ApplicationStream string `json:"application_stream,omitempty"`
	ReleaseDate       string `json:"release_date,omitempty"`
	Release           string `json:"release,omitempty"`
}

type RollingApplicationStreamTable struct {
	Title                     string                     `json:"title"`
	Major                     string                     `json:"major"`
	RollingApplicationStreams []RollingApplicationStream `json:"rolling_application_streams,omitempty"`
}

type RollingApplicationStream struct {
	RollingApplicationStream string `json:"rolling_application_stream,omitempty"`
	ReleaseDate              string `json:"release_date,omitempty"`
	ProductVersion           string `json:"product_version,omitempty"`
	PreviousRelease          string `json:"previous_release,omitempty"`
}

type DependentApplicationStreamTable struct {
	Title              string                       `json:"title"`
	Major              string                       `json:"major"`
	ApplicationStreams []DependentApplicationStream `json:"application_streams,omitempty"`
}

type DependentApplicationStream struct {
	ApplicationStream string `json:"application_stream,omitempty"`
}
