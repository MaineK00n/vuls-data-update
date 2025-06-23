package v2

// Top level structure for CVE JSON API 2.0 data
// https://csrc.nist.gov/schema/nvd/api/2.0/cpematch_api_json_2.0.schema
type api20 struct {
	ResultsPerPage int    `json:"resultsPerPage"`
	StartIndex     int    `json:"startIndex"`
	TotalResults   int    `json:"totalResults"`
	Format         string `json:"format"`
	Version        string `json:"version"`
	Timestamp      string `json:"timestamp"`
	MatchData      []struct {
		MatchCriteria MatchCriteria `json:"matchString"`
	} `json:"matchStrings"`
}

// CPE match string or range
// Top level structure that fetch command stores CPE match json files
type MatchCriteria struct {
	Criteria              string  `json:"criteria"`
	MatchCriteriaID       string  `json:"matchCriteriaId"`
	VersionStartExcluding string  `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string  `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string  `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string  `json:"versionEndIncluding,omitempty"`
	Created               string  `json:"created"`
	LastModified          string  `json:"lastModified"`
	CPELastModified       string  `json:"cpeLastModified,omitempty"`
	Status                string  `json:"status"`
	Matches               []Match `json:"matches,omitempty"`
}

type Match struct {
	CPEName   string `json:"cpeName"`
	CPENameID string `json:"cpeNameId"`
}
