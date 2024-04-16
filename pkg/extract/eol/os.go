package eol

import (
	"time"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
)

var os = map[string]map[string]types.EOLDictionary{
	detection.EcosystemTypeAlma: {
		"8": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 5, 1, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2029, 3, 1, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"9": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeAlpine: {
		"2.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2012, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"2.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2013, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"2.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2013, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"2.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2014, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"2.5": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2014, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"2.6": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2015, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"2.7": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2015, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2016, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2016, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2017, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2017, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.5": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.6": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2019, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.7": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2019, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.8": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2020, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.9": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2020, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.10": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.11": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.12": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.13": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2022, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.14": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.15": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.16": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2024, 5, 23, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.17": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2024, 11, 22, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.18": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2025, 5, 9, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3.19": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2025, 11, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
	},
	detection.EcosystemTypeAmazon: {
		"1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"2022": {Ended: true},
		"2023": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2025, 3, 15, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2028, 3, 15, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeArch: {"arch": {Ended: false}},
	"centos": {
		"3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":        func() *time.Time { t := time.Date(2006, 7, 20, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance": func() *time.Time { t := time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":        func() *time.Time { t := time.Date(2009, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance": func() *time.Time { t := time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"5": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":        func() *time.Time { t := time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance": func() *time.Time { t := time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"6": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":        func() *time.Time { t := time.Date(2017, 5, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance": func() *time.Time { t := time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"7": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":        func() *time.Time { t := time.Date(2020, 8, 6, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance": func() *time.Time { t := time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"8": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":        func() *time.Time { t := time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance": func() *time.Time { t := time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	"centos stream": {
		"8": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"9": {Ended: false},
	},
	detection.EcosystemTypeDebian: {
		"buzz": {Ended: true},
		"rex":  {Ended: true},
		"bo":   {Ended: true},
		"hamm": {Ended: true},
		"slink": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2000, 9, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTS":      func() *time.Time { t := time.Date(2000, 10, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"potato": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2003, 6, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"woody": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2006, 6, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"sarge": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2008, 3, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"etch": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2010, 2, 15, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"lenny": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2012, 2, 6, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"squeeze": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2014, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTS":      func() *time.Time { t := time.Date(2016, 2, 29, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"wheezy": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2016, 4, 25, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTS":      func() *time.Time { t := time.Date(2018, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELTS":     func() *time.Time { t := time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"jessie": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2018, 6, 17, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTS":      func() *time.Time { t := time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELTS":     func() *time.Time { t := time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"stretch": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 7, 18, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTS":      func() *time.Time { t := time.Date(2022, 7, 1, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELTS":     func() *time.Time { t := time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"buster": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 9, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTS":      func() *time.Time { t := time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"bullseye": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 7, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"bookworm": {Ended: false},
		"trixie":   {Ended: false},
		"forky":    {Ended: false},
	},
	detection.EcosystemTypeFedora: {
		"1": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2004, 9, 19, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2005, 4, 10, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"3": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2006, 1, 15, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2006, 8, 6, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"5": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2007, 7, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"6": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2007, 12, 6, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"7": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2008, 6, 12, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"8": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2009, 1, 6, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"9": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2009, 7, 9, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"10": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2009, 12, 16, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"11": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2010, 6, 24, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"12": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2010, 12, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"13": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2011, 6, 23, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"14": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2011, 12, 8, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"15": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2012, 6, 25, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"16": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2013, 2, 11, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"17": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2013, 7, 29, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"18": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2014, 1, 13, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"19": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2015, 1, 5, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"20": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2015, 6, 22, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"21": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2015, 11, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"22": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2016, 7, 18, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"23": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2016, 12, 19, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"24": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2017, 8, 7, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"25": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2017, 12, 11, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"26": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 5, 28, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"27": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 11, 29, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"28": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2019, 5, 27, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"29": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2019, 11, 25, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"30": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2020, 5, 25, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"31": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2020, 11, 23, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"32": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 5, 24, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"33": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 11, 29, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"34": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2022, 6, 6, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"35": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2022, 12, 12, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"36": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 5, 15, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"37": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 12, 4, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"38": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2024, 5, 14, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"39": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2024, 11, 12, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"40": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2025, 5, 13, 23, 59, 59, 0, time.UTC); return &t }()},
		},
	},
	detection.EcosystemTypeFreeBSD: {
		"stable/4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2007, 1, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/4.11": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2007, 1, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/5": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/5.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/5.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/5.5": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/6": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2010, 11, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/6.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2007, 1, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/6.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/6.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/6.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2010, 1, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/6.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2010, 11, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/7": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2013, 2, 28, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/7.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2009, 4, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/7.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2011, 2, 28, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/7.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2010, 6, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/7.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2012, 3, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/7.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2013, 2, 28, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/8": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2015, 8, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/8.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2010, 11, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/8.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2012, 7, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/8.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2012, 7, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/8.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2014, 4, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/8.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2015, 8, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/9": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/9.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2013, 3, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/9.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2014, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/9.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2014, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/9.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/10": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 10, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/10.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2015, 2, 28, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/10.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/10.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/10.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Extended": func() *time.Time { t := time.Date(2018, 4, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/10.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 10, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/11": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/11.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2017, 11, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/11.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 9, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/11.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2019, 10, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/11.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2020, 9, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/11.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/12": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/12.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2020, 2, 29, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/12.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/12.2": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/12.3": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 3, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/12.4": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"stable/13": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/13.0": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2022, 8, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/13.1": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 7, 31, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/13.2": {Ended: false},
		"stable/14": {
			Ended: false,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2028, 11, 30, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"releng/14.0": {Ended: false},
		"releng/14.1": {Ended: false},
	},
	detection.EcosystemTypeGentoo: {"gentoo": {Ended: false}},
	detection.EcosystemTypeNetBSD: {
		"1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2004, 12, 8, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2006, 5, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2005, 12, 22, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2008, 8, 21, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2007, 12, 18, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2009, 5, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2009, 4, 28, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"5": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2012, 10, 16, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2015, 11, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"6": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2015, 9, 24, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2018, 8, 23, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"7": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2018, 7, 16, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"8": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 2, 13, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": nil,
			},
		},
		"9": {Ended: false},
	},
	detection.EcosystemTypeOracle: {
		"3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2011, 9, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2013, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"5": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended": func() *time.Time { t := time.Date(2020, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"6": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2021, 2, 28, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended": func() *time.Time { t := time.Date(2024, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"7": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended": func() *time.Time { t := time.Date(2028, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"8": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2029, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended": func() *time.Time { t := time.Date(2032, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"9": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended": func() *time.Time { t := time.Date(2035, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeRedHat: {
		"3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":         func() *time.Time { t := time.Date(2006, 7, 20, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance1": func() *time.Time { t := time.Date(2007, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance2": func() *time.Time { t := time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELS":          func() *time.Time { t := time.Date(2014, 1, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELP":          func() *time.Time { t := time.Date(2014, 1, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":         func() *time.Time { t := time.Date(2009, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance1": func() *time.Time { t := time.Date(2011, 2, 16, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance2": func() *time.Time { t := time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELS":          func() *time.Time { t := time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELP":          func() *time.Time { t := time.Date(2022, 5, 18, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"5": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         func() *time.Time { t := time.Date(2013, 1, 8, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance1": func() *time.Time { t := time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance2": func() *time.Time { t := time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELS":          func() *time.Time { t := time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELP":          nil,
			},
		},
		"6": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         func() *time.Time { t := time.Date(2016, 5, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance1": func() *time.Time { t := time.Date(2017, 5, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance2": func() *time.Time { t := time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELS":          func() *time.Time { t := time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELP":          nil,
			},
		},
		"7": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         func() *time.Time { t := time.Date(2019, 8, 6, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance1": func() *time.Time { t := time.Date(2020, 8, 6, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance2": func() *time.Time { t := time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELS":          func() *time.Time { t := time.Date(2028, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELP":          nil,
			},
		},
		"8": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         func() *time.Time { t := time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance2": func() *time.Time { t := time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELS":          func() *time.Time { t := time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELP":          nil,
			},
		},
		"9": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         func() *time.Time { t := time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Maintenance2": func() *time.Time { t := time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELS":          func() *time.Time { t := time.Date(2035, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"ELP":          nil,
			},
		},
	},
	detection.EcosystemTypeRocky: {
		"8": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"9": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"Security": func() *time.Time { t := time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeOpenSUSE: {
		"9.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2006, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"9.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"9.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2007, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2007, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2008, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2009, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2010, 7, 26, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2011, 1, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2011, 5, 12, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2012, 1, 20, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2012, 11, 5, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2013, 5, 15, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2014, 1, 15, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2015, 1, 29, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"13.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2016, 2, 3, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"13.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2017, 1, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"tumbleweed": {Ended: false},
	},
	"opensuse leap": {
		"42.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2017, 5, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"42.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2018, 1, 26, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"42.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2019, 7, 1, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2019, 12, 3, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2021, 2, 2, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 1, 4, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2023, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.5": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeSUSEServer: {
		"10": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2007, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2007, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2008, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2010, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2013, 4, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2011, 10, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2014, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"10.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2013, 7, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2016, 7, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2012, 8, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2015, 8, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2017, 1, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2016, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2019, 1, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2016, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2019, 7, 1, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2020, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2018, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2021, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2019, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2022, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2023, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.5": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2024, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2027, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.3": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.5": {Ended: false},
		"15.6": {Ended: false},
		"15.7": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"LTSS":    func() *time.Time { t := time.Date(2031, 7, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeSUSEDesktop: {
		"11": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2012, 8, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2016, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"11.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2016, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2016, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2018, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2019, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"12.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.3": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"15.5": {Ended: false},
		"15.6": {Ended: false},
		"15.7": {
			Ended: false,
			Date: map[string]*time.Time{
				"General": func() *time.Time { t := time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeUbuntu: {
		"warty": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2006, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"hoary": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"breezy": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2007, 4, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"dapper": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(desktop)": func() *time.Time { t := time.Date(2009, 7, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(server)":  func() *time.Time { t := time.Date(2011, 6, 1, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"edgy": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2008, 4, 26, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"feisty": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2008, 10, 19, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"gutsy": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2009, 4, 18, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"hardy": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(desktop)": func() *time.Time { t := time.Date(2011, 5, 12, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(server)":  func() *time.Time { t := time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"intrepid": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2010, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"jaunty": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2010, 10, 23, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"karmic": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2011, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"lucid": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(desktop)": func() *time.Time { t := time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(server)":  func() *time.Time { t := time.Date(2015, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"maverick": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2012, 4, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"natty": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2012, 10, 28, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"oneiric": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"precise": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2017, 4, 28, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESM":      func() *time.Time { t := time.Date(2019, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"quantal": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2014, 5, 16, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"raring": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2014, 1, 27, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"saucy": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2014, 7, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"trusty": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2019, 4, 25, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESM":      func() *time.Time { t := time.Date(2024, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"utopic": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2015, 7, 23, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"vivid": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2016, 2, 4, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"wily": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2016, 7, 28, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"xenial": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2021, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESM":      func() *time.Time { t := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"yakkety": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2017, 7, 20, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"zesty": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2018, 1, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"artful": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2018, 7, 19, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"bionic": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2023, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESM":      func() *time.Time { t := time.Date(2028, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"cosmic": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2019, 7, 18, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"disco": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 1, 23, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"eoan": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 7, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"focal": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2025, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESM":      func() *time.Time { t := time.Date(2030, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"groovy": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2021, 7, 22, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"hirsute": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 1, 20, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"impish": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 7, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"jammy": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"kinetic": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2023, 7, 20, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"lunar": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 1, 25, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"mantic": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 7, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"noble": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2029, 6, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	detection.EcosystemTypeWindows: {
		"Windows XP": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard":        func() *time.Time { t := time.Date(2005, 8, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 1":  func() *time.Time { t := time.Date(2006, 10, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 1a": func() *time.Time { t := time.Date(2006, 10, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 2":  func() *time.Time { t := time.Date(2010, 7, 13, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 3":  func() *time.Time { t := time.Date(2014, 4, 8, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Vista": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard":       func() *time.Time { t := time.Date(2010, 4, 13, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 1": func() *time.Time { t := time.Date(2011, 7, 12, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 2": func() *time.Time { t := time.Date(2017, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 7": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard":                        func() *time.Time { t := time.Date(2013, 4, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 1":                  func() *time.Time { t := time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 1": func() *time.Time { t := time.Date(2021, 1, 12, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 2": func() *time.Time { t := time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 3": func() *time.Time { t := time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 8": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2016, 1, 12, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 8.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2018, 1, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESU":      func() *time.Time { t := time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1507": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2017, 5, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1511": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2017, 10, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1607": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2018, 4, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1703": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2018, 10, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2019, 10, 8, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1709": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2020, 10, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1803": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2019, 11, 12, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1809": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2020, 11, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1903": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 12, 8, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 1909": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2022, 5, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 2004": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2021, 12, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 20H2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2022, 5, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2023, 5, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 21H1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 12, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 21H2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2023, 6, 13, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2024, 6, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 10 Version 22H2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 11 Version 21H2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 11 Version 22H2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows 11 Version 23H2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard(Home and Pro)":             func() *time.Time { t := time.Date(2025, 11, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"Standard(Enterprise and Education)": func() *time.Time { t := time.Date(2026, 11, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2003": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard":       func() *time.Time { t := time.Date(2007, 4, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 1": func() *time.Time { t := time.Date(2009, 4, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 2": func() *time.Time { t := time.Date(2015, 7, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2003 R2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard":       func() *time.Time { t := time.Date(2009, 4, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 2": func() *time.Time { t := time.Date(2015, 7, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2008": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard":                                     func() *time.Time { t := time.Date(2011, 7, 12, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 2":                               func() *time.Time { t := time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 1":              func() *time.Time { t := time.Date(2021, 1, 12, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 2":              func() *time.Time { t := time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 3":              func() *time.Time { t := time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 4 (Azure only)": func() *time.Time { t := time.Date(2024, 1, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2008 R2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard":                                     func() *time.Time { t := time.Date(2013, 4, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"Service Pack 1":                               func() *time.Time { t := time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 1":              func() *time.Time { t := time.Date(2021, 1, 12, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 2":              func() *time.Time { t := time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 3":              func() *time.Time { t := time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 4 (Azure only)": func() *time.Time { t := time.Date(2024, 1, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2012": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard":                        func() *time.Time { t := time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 1": func() *time.Time { t := time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 2": func() *time.Time { t := time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 3": func() *time.Time { t := time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2012 R2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard":                        func() *time.Time { t := time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 1": func() *time.Time { t := time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 2": func() *time.Time { t := time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"Extended Security Update Year 3": func() *time.Time { t := time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2016": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESU":      func() *time.Time { t := time.Date(2027, 1, 12, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server, Version 1709": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server, Version 1803": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2019, 11, 12, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server, Version 1809": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 11, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2019": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2024, 1, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESU":      func() *time.Time { t := time.Date(2029, 1, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server, Version 1903": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2020, 12, 8, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server, Version 1909": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server, Version 2004": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2021, 12, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server, Version 20H2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2022, 8, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"Windows Server 2022": {
			Ended: false,
			Date: map[string]*time.Time{
				"Standard": func() *time.Time { t := time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC); return &t }(),
				"ESU":      func() *time.Time { t := time.Date(2031, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
	"macos": {
		"10.0": {Ended: true},
		"10.1": {Ended: true},
		"10.2": {Ended: true},
		"10.3": {Ended: true},
		"10.4": {Ended: true},
		"10.5": {Ended: true},
		"10.6": {Ended: true},
		"10.7": {Ended: true},
		"10.8": {Ended: true},
		"10.9": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2016, 12, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"10.10": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2017, 8, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"10.11": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2018, 12, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"10.12": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2019, 10, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"10.13": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2020, 12, 1, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"10.14": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2021, 10, 25, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"10.15": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2022, 9, 12, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"11": {
			Ended: true,
			Date:  map[string]*time.Time{"Standard": func() *time.Time { t := time.Date(2023, 9, 26, 23, 59, 59, 0, time.UTC); return &t }()},
		},
		"12": {Ended: false},
		"13": {Ended: false},
		"14": {Ended: false},
	},
	detection.EcosystemTypeFortinet: {
		"FortiOS 4.2": {
			Ended: true,
		},
		"FortiOS 5.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2018, 12, 21, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2020, 6, 21, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiOS 5.6": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 3, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiOS 6.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 3, 29, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 9, 29, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiOS 6.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 3, 28, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 9, 28, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiOS 6.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 9, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiOS 7.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2024, 3, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2025, 9, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiOS 7.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 3, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiOS 7.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2026, 5, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2027, 11, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 5.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2017, 9, 4, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2019, 3, 4, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 5.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2019, 2, 17, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2020, 8, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 5.6": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 7, 27, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 1, 27, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 6.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 4, 18, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 10, 18, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 6.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 10, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 6.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 4, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 10, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 7.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2024, 4, 22, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2025, 10, 22, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 7.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 10, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAnalyzer 7.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2026, 5, 15, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2027, 11, 15, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 5.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2017, 8, 25, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2019, 2, 25, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 5.3": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2018, 11, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2020, 5, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 5.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 7, 25, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 1, 25, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 6.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 5, 29, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 11, 29, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 6.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 8, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 2, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 6.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 5, 8, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 11, 8, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 7.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2024, 5, 17, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2025, 11, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiMail 7.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 5, 10, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 11, 10, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 5.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2017, 8, 23, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2019, 2, 23, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 5.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2019, 2, 17, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2020, 8, 17, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 5.6": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 7, 27, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 1, 27, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 6.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 4, 18, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 10, 18, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 6.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 10, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 6.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 4, 9, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 10, 9, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 7.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2024, 4, 22, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2025, 10, 22, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiManager 7.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 10, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 5.6": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2019, 9, 26, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2019, 9, 26, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 5.7": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 1, 18, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2021, 7, 18, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 5.8": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 4, 27, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2021, 10, 27, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 5.9": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 3, 20, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 9, 20, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 6.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 5, 23, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 11, 23, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 6.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 3, 27, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 9, 27, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 6.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 9, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 3, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 6.3": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 1, 21, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 7, 21, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 6.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 4, 1, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 10, 1, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 7.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 1, 19, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 7, 19, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiWeb 7.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 1, 16, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2027, 6, 16, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAP 5.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2019, 1, 8, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2020, 7, 8, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAP 5.6": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 4, 13, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2021, 10, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAP 6.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 10, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAP 6.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 4, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAP 6.4": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 4, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAP 7.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2024, 4, 20, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2025, 10, 20, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiAP 7.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 4, 14, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 10, 14, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiSandbox 2.4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 5, 3, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2021, 11, 3, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiSandbox 2.5": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2020, 11, 2, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 5, 2, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiSandbox 3.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 7, 31, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 1, 31, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiSandbox 3.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 6, 18, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 12, 18, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiSandbox 3.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 4, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2024, 10, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiSandbox 4.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2024, 4, 19, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2025, 10, 19, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiSandbox 4.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 4, 13, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiProxy 1.0": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 4, 11, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2022, 10, 11, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiProxy 1.1": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2021, 12, 22, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 6, 22, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiProxy 1.2": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2022, 1, 30, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2023, 7, 30, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiProxy 2.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2023, 11, 15, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2025, 5, 15, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiProxy 7.0": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2024, 8, 24, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2026, 2, 24, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
		"FortiProxy 7.2": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full": func() *time.Time { t := time.Date(2025, 9, 20, 23, 59, 59, 0, time.UTC); return &t }(),
				"EOS":  func() *time.Time { t := time.Date(2027, 3, 20, 23, 59, 59, 0, time.UTC); return &t }(),
			},
		},
	},
}
