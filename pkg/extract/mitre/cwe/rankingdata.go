package cwe

// rankingEntry is a CWE's placement (rank == slice index + 1) in a ranking
// list, with its published score (0 when the source published none).
type rankingEntry struct {
	cwe   string
	score float64
}

// supplementalRankings carries ranking data published only as HTML tables on
// the MITRE archive pages, absent from the fetched CWE catalog: the per-CWE
// score for each yearly "CWE Top 25" list, and the rank+score for the
// discontinued "CWE/SANS Top 25" lists (whose flat ranking the catalog does
// not encode). Keyed by the list's view CWE ID; entries are in published rank
// order. Transcribed from the pages below and cross-checked against their
// tables; extend and re-verify when MITRE publishes a new CWE Top 25.
//
//	CWE-750  https://cwe.mitre.org/top25/archive/2009/2009_cwe_sans_top25.html
//	CWE-800  https://cwe.mitre.org/top25/archive/2010/2010_cwe_sans_top25.html
//	CWE-900  https://cwe.mitre.org/top25/archive/2011/2011_cwe_sans_top25.html
//	CWE-1337 https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html
//	CWE-1350 https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html
//	CWE-1387 https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html
//	CWE-1425 https://cwe.mitre.org/top25/archive/2023/2023_cwe_top25.html
//	CWE-1430 https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html
//	CWE-1435 https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
var supplementalRankings = map[string][]rankingEntry{
	"CWE-750": { // 2009 CWE/SANS Top 25 Most Dangerous Programming Errors (no published scores)
		{"CWE-20", 0}, {"CWE-116", 0}, {"CWE-89", 0}, {"CWE-79", 0}, {"CWE-78", 0},
		{"CWE-319", 0}, {"CWE-352", 0}, {"CWE-362", 0}, {"CWE-209", 0}, {"CWE-119", 0},
		{"CWE-642", 0}, {"CWE-73", 0}, {"CWE-426", 0}, {"CWE-94", 0}, {"CWE-494", 0},
		{"CWE-404", 0}, {"CWE-665", 0}, {"CWE-682", 0}, {"CWE-285", 0}, {"CWE-327", 0},
		{"CWE-259", 0}, {"CWE-732", 0}, {"CWE-330", 0}, {"CWE-250", 0}, {"CWE-602", 0},
	},
	"CWE-800": { // 2010 CWE/SANS Top 25 Most Dangerous Programming Errors
		{"CWE-79", 346}, {"CWE-89", 330}, {"CWE-120", 273}, {"CWE-352", 261}, {"CWE-285", 219},
		{"CWE-807", 202}, {"CWE-22", 197}, {"CWE-434", 194}, {"CWE-78", 188}, {"CWE-311", 188},
		{"CWE-798", 176}, {"CWE-805", 158}, {"CWE-98", 157}, {"CWE-129", 156},
		{"CWE-754", 155}, {"CWE-209", 154}, {"CWE-190", 154}, {"CWE-131", 153},
		{"CWE-306", 147}, {"CWE-494", 146}, {"CWE-732", 145}, {"CWE-770", 145},
		{"CWE-601", 142}, {"CWE-327", 141}, {"CWE-362", 138},
	},
	"CWE-900": { // 2011 CWE/SANS Top 25 Most Dangerous Software Errors
		{"CWE-89", 93.8}, {"CWE-78", 83.3}, {"CWE-120", 79.0}, {"CWE-79", 77.7},
		{"CWE-306", 76.9}, {"CWE-862", 76.8}, {"CWE-798", 75.0}, {"CWE-311", 75.0},
		{"CWE-434", 74.0}, {"CWE-807", 73.8}, {"CWE-250", 73.1}, {"CWE-352", 70.1},
		{"CWE-22", 69.3}, {"CWE-494", 68.5}, {"CWE-863", 67.8}, {"CWE-829", 66.0},
		{"CWE-732", 65.5}, {"CWE-676", 64.6}, {"CWE-327", 64.1}, {"CWE-131", 62.4},
		{"CWE-307", 61.5}, {"CWE-601", 61.1}, {"CWE-134", 61.0}, {"CWE-190", 60.3},
		{"CWE-759", 59.9},
	},
	"CWE-1337": { // 2021 CWE Top 25 Most Dangerous Software Weaknesses
		{"CWE-787", 65.93}, {"CWE-79", 46.84}, {"CWE-125", 24.9}, {"CWE-20", 20.47},
		{"CWE-78", 19.55}, {"CWE-89", 19.54}, {"CWE-416", 16.83}, {"CWE-22", 14.69},
		{"CWE-352", 14.46}, {"CWE-434", 8.45}, {"CWE-306", 7.93}, {"CWE-190", 7.12},
		{"CWE-502", 6.71}, {"CWE-287", 6.58}, {"CWE-476", 6.54}, {"CWE-798", 6.27},
		{"CWE-119", 5.84}, {"CWE-862", 5.47}, {"CWE-276", 5.09}, {"CWE-200", 4.74},
		{"CWE-522", 4.21}, {"CWE-732", 4.2}, {"CWE-611", 4.02}, {"CWE-918", 3.78},
		{"CWE-77", 3.58},
	},
	"CWE-1350": { // 2020 CWE Top 25 Most Dangerous Software Weaknesses
		{"CWE-79", 46.82}, {"CWE-787", 46.17}, {"CWE-20", 33.47}, {"CWE-125", 26.50},
		{"CWE-119", 23.73}, {"CWE-89", 20.69}, {"CWE-200", 19.16}, {"CWE-416", 18.87},
		{"CWE-352", 17.29}, {"CWE-78", 16.44}, {"CWE-190", 15.81}, {"CWE-22", 13.67},
		{"CWE-476", 8.35}, {"CWE-287", 8.17}, {"CWE-434", 7.38}, {"CWE-732", 6.95},
		{"CWE-94", 6.53}, {"CWE-522", 5.49}, {"CWE-611", 5.33}, {"CWE-798", 5.19},
		{"CWE-502", 4.93}, {"CWE-269", 4.87}, {"CWE-400", 4.14}, {"CWE-306", 3.85},
		{"CWE-862", 3.77},
	},
	"CWE-1387": { // 2022 CWE Top 25 Most Dangerous Software Weaknesses
		{"CWE-787", 64.20}, {"CWE-79", 45.97}, {"CWE-89", 22.11}, {"CWE-20", 20.63},
		{"CWE-125", 17.67}, {"CWE-78", 17.53}, {"CWE-416", 15.50}, {"CWE-22", 14.08},
		{"CWE-352", 11.53}, {"CWE-434", 9.56}, {"CWE-476", 7.15}, {"CWE-502", 6.68},
		{"CWE-190", 6.53}, {"CWE-287", 6.35}, {"CWE-798", 5.66}, {"CWE-862", 5.53},
		{"CWE-77", 5.42}, {"CWE-306", 5.15}, {"CWE-119", 4.85}, {"CWE-276", 4.84},
		{"CWE-918", 4.27}, {"CWE-362", 3.57}, {"CWE-400", 3.56}, {"CWE-611", 3.38},
		{"CWE-94", 3.32},
	},
	"CWE-1425": { // 2023 CWE Top 25 Most Dangerous Software Weaknesses
		{"CWE-787", 63.72}, {"CWE-79", 45.54}, {"CWE-89", 34.27}, {"CWE-416", 16.71},
		{"CWE-78", 15.65}, {"CWE-20", 15.50}, {"CWE-125", 14.60}, {"CWE-22", 14.11},
		{"CWE-352", 11.73}, {"CWE-434", 10.41}, {"CWE-862", 6.90}, {"CWE-476", 6.59},
		{"CWE-287", 6.39}, {"CWE-190", 5.89}, {"CWE-502", 5.56}, {"CWE-77", 4.95},
		{"CWE-119", 4.75}, {"CWE-798", 4.57}, {"CWE-918", 4.56}, {"CWE-306", 3.78},
		{"CWE-362", 3.53}, {"CWE-269", 3.31}, {"CWE-94", 3.30}, {"CWE-863", 3.16},
		{"CWE-276", 3.16},
	},
	"CWE-1430": { // 2024 CWE Top 25 Most Dangerous Software Weaknesses
		{"CWE-79", 56.92}, {"CWE-787", 45.20}, {"CWE-89", 35.88}, {"CWE-352", 19.57},
		{"CWE-22", 12.74}, {"CWE-125", 11.42}, {"CWE-78", 11.30}, {"CWE-416", 10.19},
		{"CWE-862", 10.11}, {"CWE-434", 10.03}, {"CWE-94", 7.13}, {"CWE-20", 6.78},
		{"CWE-77", 6.74}, {"CWE-287", 5.94}, {"CWE-269", 5.22}, {"CWE-502", 5.07},
		{"CWE-200", 5.07}, {"CWE-863", 4.05}, {"CWE-918", 4.05}, {"CWE-119", 3.69},
		{"CWE-476", 3.58}, {"CWE-798", 3.46}, {"CWE-190", 3.37}, {"CWE-400", 3.23},
		{"CWE-306", 2.73},
	},
	"CWE-1435": { // 2025 CWE Top 25 Most Dangerous Software Weaknesses
		{"CWE-79", 60.38}, {"CWE-89", 28.72}, {"CWE-352", 13.64}, {"CWE-862", 13.28},
		{"CWE-787", 12.68}, {"CWE-22", 8.99}, {"CWE-416", 8.47}, {"CWE-125", 7.88},
		{"CWE-78", 7.85}, {"CWE-94", 7.57}, {"CWE-120", 6.96}, {"CWE-434", 6.87},
		{"CWE-476", 6.41}, {"CWE-121", 5.75}, {"CWE-502", 5.23}, {"CWE-122", 5.21},
		{"CWE-863", 4.14}, {"CWE-20", 4.09}, {"CWE-284", 4.07}, {"CWE-200", 4.01},
		{"CWE-306", 3.47}, {"CWE-918", 3.36}, {"CWE-77", 3.15}, {"CWE-639", 2.62},
		{"CWE-770", 2.54},
	},
}
