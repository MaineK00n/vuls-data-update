package eol

import (
	"time"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	eolTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/eol"
)

var os = map[string]map[string]eolTypes.EOL{
	ecosystemTypes.EcosystemTypeAlma: {
		"8": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 5, 1, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2029, 3, 1, 23, 59, 59, 0, time.UTC),
			},
		},
		"9": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeAlpine: {
		"2.1": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2012, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"2.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2013, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"2.3": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2013, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"2.4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2014, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"2.5": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2014, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"2.6": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2015, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"2.7": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2015, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2016, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.1": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2016, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2017, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.3": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2017, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.5": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.6": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2019, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.7": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2019, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.8": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2020, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.9": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2020, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.10": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.11": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.12": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.13": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2022, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.14": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.15": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
		"3.16": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2024, 5, 23, 23, 59, 59, 0, time.UTC)},
		},
		"3.17": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2024, 11, 22, 23, 59, 59, 0, time.UTC)},
		},
		"3.18": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2025, 5, 9, 23, 59, 59, 0, time.UTC)},
		},
		"3.19": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2025, 11, 1, 23, 59, 59, 0, time.UTC)},
		},
	},
	ecosystemTypes.EcosystemTypeAmazon: {
		"1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 12, 31, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"2": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"2022": {Ended: true},
		"2023": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2025, 3, 15, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2028, 3, 15, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeArch: {"arch": {Ended: false}},
	"centos": {
		"3": {
			Ended: true,
			Date: map[string]time.Time{
				"Full":        time.Date(2006, 7, 20, 23, 59, 59, 0, time.UTC),
				"Maintenance": time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full":        time.Date(2009, 3, 31, 23, 59, 59, 0, time.UTC),
				"Maintenance": time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC),
			},
		},
		"5": {
			Ended: true,
			Date: map[string]time.Time{
				"Full":        time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC),
				"Maintenance": time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"6": {
			Ended: true,
			Date: map[string]time.Time{
				"Full":        time.Date(2017, 5, 10, 23, 59, 59, 0, time.UTC),
				"Maintenance": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"7": {
			Ended: false,
			Date: map[string]time.Time{
				"Full":        time.Date(2020, 8, 6, 23, 59, 59, 0, time.UTC),
				"Maintenance": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"8": {
			Ended: true,
			Date: map[string]time.Time{
				"Full":        time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
				"Maintenance": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	"centos stream": {
		"8": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC)},
		},
		"9": {Ended: false},
	},
	ecosystemTypes.EcosystemTypeDebian: {
		"buzz": {Ended: true},
		"rex":  {Ended: true},
		"bo":   {Ended: true},
		"hamm": {Ended: true},
		"slink": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2000, 9, 30, 23, 59, 59, 0, time.UTC),
				"LTS":      time.Date(2000, 10, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"potato": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2003, 6, 30, 23, 59, 59, 0, time.UTC)},
		},
		"woody": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2006, 6, 30, 23, 59, 59, 0, time.UTC)},
		},
		"sarge": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2008, 3, 31, 23, 59, 59, 0, time.UTC)},
		},
		"etch": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2010, 2, 15, 23, 59, 59, 0, time.UTC)},
		},
		"lenny": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2012, 2, 6, 23, 59, 59, 0, time.UTC)},
		},
		"squeeze": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2014, 5, 31, 23, 59, 59, 0, time.UTC),
				"LTS":      time.Date(2016, 2, 29, 23, 59, 59, 0, time.UTC),
			},
		},
		"wheezy": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2016, 4, 25, 23, 59, 59, 0, time.UTC),
				"LTS":      time.Date(2018, 5, 31, 23, 59, 59, 0, time.UTC),
				"ELTS":     time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"jessie": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2018, 6, 17, 23, 59, 59, 0, time.UTC),
				"LTS":      time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC),
				"ELTS":     time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"stretch": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 7, 18, 23, 59, 59, 0, time.UTC),
				"LTS":      time.Date(2022, 7, 1, 23, 59, 59, 0, time.UTC),
				"ELTS":     time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"buster": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 9, 10, 23, 59, 59, 0, time.UTC),
				"LTS":      time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"bullseye": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 7, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"bookworm": {Ended: false},
		"trixie":   {Ended: false},
		"forky":    {Ended: false},
	},
	ecosystemTypes.EcosystemTypeFedora: {
		"1": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2004, 9, 19, 23, 59, 59, 0, time.UTC)},
		},
		"2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2005, 4, 10, 23, 59, 59, 0, time.UTC)},
		},
		"3": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2006, 1, 15, 23, 59, 59, 0, time.UTC)},
		},
		"4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2006, 8, 6, 23, 59, 59, 0, time.UTC)},
		},
		"5": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2007, 7, 1, 23, 59, 59, 0, time.UTC)},
		},
		"6": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2007, 12, 6, 23, 59, 59, 0, time.UTC)},
		},
		"7": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2008, 6, 12, 23, 59, 59, 0, time.UTC)},
		},
		"8": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2009, 1, 6, 23, 59, 59, 0, time.UTC)},
		},
		"9": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2009, 7, 9, 23, 59, 59, 0, time.UTC)},
		},
		"10": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2009, 12, 16, 23, 59, 59, 0, time.UTC)},
		},
		"11": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2010, 6, 24, 23, 59, 59, 0, time.UTC)},
		},
		"12": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2010, 12, 1, 23, 59, 59, 0, time.UTC)},
		},
		"13": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2011, 6, 23, 23, 59, 59, 0, time.UTC)},
		},
		"14": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2011, 12, 8, 23, 59, 59, 0, time.UTC)},
		},
		"15": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2012, 6, 25, 23, 59, 59, 0, time.UTC)},
		},
		"16": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2013, 2, 11, 23, 59, 59, 0, time.UTC)},
		},
		"17": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2013, 7, 29, 23, 59, 59, 0, time.UTC)},
		},
		"18": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2014, 1, 13, 23, 59, 59, 0, time.UTC)},
		},
		"19": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2015, 1, 5, 23, 59, 59, 0, time.UTC)},
		},
		"20": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2015, 6, 22, 23, 59, 59, 0, time.UTC)},
		},
		"21": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2015, 11, 30, 23, 59, 59, 0, time.UTC)},
		},
		"22": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2016, 7, 18, 23, 59, 59, 0, time.UTC)},
		},
		"23": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2016, 12, 19, 23, 59, 59, 0, time.UTC)},
		},
		"24": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2017, 8, 7, 23, 59, 59, 0, time.UTC)},
		},
		"25": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2017, 12, 11, 23, 59, 59, 0, time.UTC)},
		},
		"26": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 5, 28, 23, 59, 59, 0, time.UTC)},
		},
		"27": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 11, 29, 23, 59, 59, 0, time.UTC)},
		},
		"28": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2019, 5, 27, 23, 59, 59, 0, time.UTC)},
		},
		"29": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2019, 11, 25, 23, 59, 59, 0, time.UTC)},
		},
		"30": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2020, 5, 25, 23, 59, 59, 0, time.UTC)},
		},
		"31": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2020, 11, 23, 23, 59, 59, 0, time.UTC)},
		},
		"32": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 5, 24, 23, 59, 59, 0, time.UTC)},
		},
		"33": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 11, 29, 23, 59, 59, 0, time.UTC)},
		},
		"34": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2022, 6, 6, 23, 59, 59, 0, time.UTC)},
		},
		"35": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2022, 12, 12, 23, 59, 59, 0, time.UTC)},
		},
		"36": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 5, 15, 23, 59, 59, 0, time.UTC)},
		},
		"37": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 12, 4, 23, 59, 59, 0, time.UTC)},
		},
		"38": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2024, 5, 14, 23, 59, 59, 0, time.UTC)},
		},
		"39": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2024, 11, 12, 23, 59, 59, 0, time.UTC)},
		},
		"40": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2025, 5, 13, 23, 59, 59, 0, time.UTC)},
		},
	},
	ecosystemTypes.EcosystemTypeFreeBSD: {
		"stable/4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2007, 1, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/4.11": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2007, 1, 31, 23, 59, 59, 0, time.UTC)},
		},
		"stable/5": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/5.3": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/5.4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/5.5": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC)},
		},
		"stable/6": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2010, 11, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/6.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2007, 1, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/6.1": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/6.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/6.3": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2010, 1, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/6.4": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2010, 11, 30, 23, 59, 59, 0, time.UTC)},
		},
		"stable/7": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2013, 2, 28, 23, 59, 59, 0, time.UTC)},
		},
		"releng/7.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2009, 4, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/7.1": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2011, 2, 28, 23, 59, 59, 0, time.UTC)},
		},
		"releng/7.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2010, 6, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/7.3": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2012, 3, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/7.4": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2013, 2, 28, 23, 59, 59, 0, time.UTC)},
		},
		"stable/8": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2015, 8, 1, 23, 59, 59, 0, time.UTC)},
		},
		"releng/8.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2010, 11, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/8.1": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2012, 7, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/8.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2012, 7, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/8.3": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2014, 4, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/8.4": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2015, 8, 1, 23, 59, 59, 0, time.UTC)},
		},
		"stable/9": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/9.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2013, 3, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/9.1": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2014, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/9.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2014, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/9.3": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"stable/10": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 10, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/10.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2015, 2, 28, 23, 59, 59, 0, time.UTC)},
		},
		"releng/10.1": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/10.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2016, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/10.3": {
			Ended: true,
			Date:  map[string]time.Time{"Extended": time.Date(2018, 4, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/10.4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 10, 31, 23, 59, 59, 0, time.UTC)},
		},
		"stable/11": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/11.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2017, 11, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/11.1": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 9, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/11.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2019, 10, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/11.3": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2020, 9, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/11.4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC)},
		},
		"stable/12": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/12.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2020, 2, 29, 23, 59, 59, 0, time.UTC)},
		},
		"releng/12.1": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/12.2": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/12.3": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 3, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/12.4": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)},
		},
		"stable/13": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/13.0": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2022, 8, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/13.1": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 7, 31, 23, 59, 59, 0, time.UTC)},
		},
		"releng/13.2": {Ended: false},
		"stable/14": {
			Ended: false,
			Date:  map[string]time.Time{"Standard": time.Date(2028, 11, 30, 23, 59, 59, 0, time.UTC)},
		},
		"releng/14.0": {Ended: false},
		"releng/14.1": {Ended: false},
	},
	ecosystemTypes.EcosystemTypeGentoo: {"gentoo": {Ended: false}},
	ecosystemTypes.EcosystemTypeNetBSD: {
		"1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2004, 12, 8, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2006, 5, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2005, 12, 22, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2008, 8, 21, 23, 59, 59, 0, time.UTC),
			},
		},
		"3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2007, 12, 18, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2009, 5, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2009, 4, 28, 23, 59, 59, 0, time.UTC),
			},
		},
		"5": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2012, 10, 16, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2015, 11, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"6": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2015, 9, 24, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2018, 8, 23, 23, 59, 59, 0, time.UTC),
			},
		},
		"7": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2018, 7, 16, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"8": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 2, 13, 23, 59, 59, 0, time.UTC),
				// "Security": time.Date(),
			},
		},
		"9": {Ended: false},
	},
	ecosystemTypes.EcosystemTypeOracle: {
		"3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2011, 9, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2013, 1, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"5": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
				"Extended": time.Date(2020, 10, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"6": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2021, 2, 28, 23, 59, 59, 0, time.UTC),
				"Extended": time.Date(2024, 11, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"7": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 11, 30, 23, 59, 59, 0, time.UTC),
				"Extended": time.Date(2028, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"8": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2029, 6, 30, 23, 59, 59, 0, time.UTC),
				"Extended": time.Date(2032, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"9": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
				"Extended": time.Date(2035, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeRedHat: {
		"3": {
			Ended: true,
			Date: map[string]time.Time{
				"Full":         time.Date(2006, 7, 20, 23, 59, 59, 0, time.UTC),
				"Maintenance1": time.Date(2007, 6, 30, 23, 59, 59, 0, time.UTC),
				"Maintenance2": time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC),
				"ELS":          time.Date(2014, 1, 30, 23, 59, 59, 0, time.UTC),
				"ELP":          time.Date(2014, 1, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full":         time.Date(2009, 3, 31, 23, 59, 59, 0, time.UTC),
				"Maintenance1": time.Date(2011, 2, 16, 23, 59, 59, 0, time.UTC),
				"Maintenance2": time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC),
				"ELS":          time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC),
				"ELP":          time.Date(2022, 5, 18, 23, 59, 59, 0, time.UTC),
			},
		},
		"5": {
			Ended: false,
			Date: map[string]time.Time{
				"Full":         time.Date(2013, 1, 8, 23, 59, 59, 0, time.UTC),
				"Maintenance1": time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC),
				"Maintenance2": time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC),
				"ELS":          time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
				// "ELP":          time.Date(),
			},
		},
		"6": {
			Ended: false,
			Date: map[string]time.Time{
				"Full":         time.Date(2016, 5, 10, 23, 59, 59, 0, time.UTC),
				"Maintenance1": time.Date(2017, 5, 10, 23, 59, 59, 0, time.UTC),
				"Maintenance2": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
				"ELS":          time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
				// "ELP":          time.Date(),
			},
		},
		"7": {
			Ended: false,
			Date: map[string]time.Time{
				"Full":         time.Date(2019, 8, 6, 23, 59, 59, 0, time.UTC),
				"Maintenance1": time.Date(2020, 8, 6, 23, 59, 59, 0, time.UTC),
				"Maintenance2": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
				"ELS":          time.Date(2028, 6, 30, 23, 59, 59, 0, time.UTC),
				// "ELP":          time.Date(),
			},
		},
		"8": {
			Ended: false,
			Date: map[string]time.Time{
				"Full":         time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC),
				"Maintenance2": time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC),
				"ELS":          time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
				// "ELP":          time.Date(),
			},
		},
		"9": {
			Ended: false,
			Date: map[string]time.Time{
				"Full":         time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC),
				"Maintenance2": time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
				"ELS":          time.Date(2035, 5, 31, 23, 59, 59, 0, time.UTC),
				// "ELP":          time.Date(),
			},
		},
	},
	ecosystemTypes.EcosystemTypeRocky: {
		"8": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"9": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC),
				"Security": time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeOpenSUSE: {
		"9.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2006, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"9.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"9.3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2007, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2007, 11, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2008, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2008, 11, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2009, 10, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2010, 7, 26, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2011, 1, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2011, 5, 12, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2012, 1, 20, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2012, 11, 5, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2013, 5, 15, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2014, 1, 15, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2015, 1, 29, 23, 59, 59, 0, time.UTC),
			},
		},
		"13.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2016, 2, 3, 23, 59, 59, 0, time.UTC),
			},
		},
		"13.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2017, 1, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"tumbleweed": {Ended: false},
	},
	"opensuse leap": {
		"42.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2017, 5, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"42.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2018, 1, 26, 23, 59, 59, 0, time.UTC),
			},
		},
		"42.3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2019, 7, 1, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2019, 12, 3, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2021, 2, 2, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 1, 4, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.3": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 11, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2023, 11, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.5": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeSUSEServer: {
		"10": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2007, 12, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2007, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.1": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2008, 11, 30, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.2": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2010, 4, 11, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2013, 4, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.3": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2011, 10, 11, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2014, 10, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"10.4": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2013, 7, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2016, 7, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"11": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.1": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2012, 8, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2015, 8, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.2": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2017, 1, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.3": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2016, 1, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2019, 1, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.4": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2019, 3, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2022, 3, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"12": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2016, 6, 30, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2019, 7, 1, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.1": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2020, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.2": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2018, 3, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2021, 3, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.3": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2019, 6, 30, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2022, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.4": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2020, 6, 30, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2023, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.5": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2024, 10, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2027, 10, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.1": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.2": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.3": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.4": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.5": {Ended: false},
		"15.6": {Ended: false},
		"15.7": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC),
				"LTSS":    time.Date(2031, 7, 31, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeSUSEDesktop: {
		"11": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2010, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.1": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2012, 8, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.2": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2014, 1, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.3": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2016, 1, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"11.4": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2016, 3, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"12": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2016, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.1": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.2": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2018, 3, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.3": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2019, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"12.4": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2019, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.1": {
			Ended: true,
			Date: map[string]time.Time{
				"General": time.Date(2021, 1, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.2": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.3": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.4": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"15.5": {Ended: false},
		"15.6": {Ended: false},
		"15.7": {
			Ended: false,
			Date: map[string]time.Time{
				"General": time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeUbuntu: {
		"warty": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2006, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"hoary": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"breezy": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2007, 4, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"dapper": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(desktop)": time.Date(2009, 7, 14, 23, 59, 59, 0, time.UTC),
				"Standard(server)":  time.Date(2011, 6, 1, 23, 59, 59, 0, time.UTC),
			},
		},
		"edgy": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2008, 4, 26, 23, 59, 59, 0, time.UTC),
			},
		},
		"feisty": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2008, 10, 19, 23, 59, 59, 0, time.UTC),
			},
		},
		"gutsy": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2009, 4, 18, 23, 59, 59, 0, time.UTC),
			},
		},
		"hardy": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(desktop)": time.Date(2011, 5, 12, 23, 59, 59, 0, time.UTC),
				"Standard(server)":  time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"intrepid": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2010, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"jaunty": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2010, 10, 23, 23, 59, 59, 0, time.UTC),
			},
		},
		"karmic": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2011, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"lucid": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(desktop)": time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC),
				"Standard(server)":  time.Date(2015, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"maverick": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2012, 4, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"natty": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2012, 10, 28, 23, 59, 59, 0, time.UTC),
			},
		},
		"oneiric": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"precise": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2017, 4, 28, 23, 59, 59, 0, time.UTC),
				"ESM":      time.Date(2019, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"quantal": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2014, 5, 16, 23, 59, 59, 0, time.UTC),
			},
		},
		"raring": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2014, 1, 27, 23, 59, 59, 0, time.UTC),
			},
		},
		"saucy": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2014, 7, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"trusty": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2019, 4, 25, 23, 59, 59, 0, time.UTC),
				"ESM":      time.Date(2024, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"utopic": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2015, 7, 23, 23, 59, 59, 0, time.UTC),
			},
		},
		"vivid": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2016, 2, 4, 23, 59, 59, 0, time.UTC),
			},
		},
		"wily": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2016, 7, 28, 23, 59, 59, 0, time.UTC),
			},
		},
		"xenial": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2021, 4, 30, 23, 59, 59, 0, time.UTC),
				"ESM":      time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"yakkety": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2017, 7, 20, 23, 59, 59, 0, time.UTC),
			},
		},
		"zesty": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2018, 1, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"artful": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2018, 7, 19, 23, 59, 59, 0, time.UTC),
			},
		},
		"bionic": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2023, 6, 30, 23, 59, 59, 0, time.UTC),
				"ESM":      time.Date(2028, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"cosmic": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2019, 7, 18, 23, 59, 59, 0, time.UTC),
			},
		},
		"disco": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 1, 23, 23, 59, 59, 0, time.UTC),
			},
		},
		"eoan": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 7, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"focal": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2025, 4, 30, 23, 59, 59, 0, time.UTC),
				"ESM":      time.Date(2030, 4, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"groovy": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2021, 7, 22, 23, 59, 59, 0, time.UTC),
			},
		},
		"hirsute": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 1, 20, 23, 59, 59, 0, time.UTC),
			},
		},
		"impish": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 7, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"jammy": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"kinetic": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2023, 7, 20, 23, 59, 59, 0, time.UTC),
			},
		},
		"lunar": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 1, 25, 23, 59, 59, 0, time.UTC),
			},
		},
		"mantic": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 7, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"noble": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2029, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		},
	},
	ecosystemTypes.EcosystemTypeWindows: {
		"Windows XP": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard":        time.Date(2005, 8, 30, 23, 59, 59, 0, time.UTC),
				"Service Pack 1":  time.Date(2006, 10, 10, 23, 59, 59, 0, time.UTC),
				"Service Pack 1a": time.Date(2006, 10, 10, 23, 59, 59, 0, time.UTC),
				"Service Pack 2":  time.Date(2010, 7, 13, 23, 59, 59, 0, time.UTC),
				"Service Pack 3":  time.Date(2014, 4, 8, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Vista": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard":       time.Date(2010, 4, 13, 23, 59, 59, 0, time.UTC),
				"Service Pack 1": time.Date(2011, 7, 12, 23, 59, 59, 0, time.UTC),
				"Service Pack 2": time.Date(2017, 4, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 7": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard":                        time.Date(2013, 4, 9, 23, 59, 59, 0, time.UTC),
				"Service Pack 1":                  time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 1": time.Date(2021, 1, 12, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 2": time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 3": time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 8": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2016, 1, 12, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 8.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2018, 1, 9, 23, 59, 59, 0, time.UTC),
				"ESU":      time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1507": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2017, 5, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1511": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2017, 10, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1607": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2018, 4, 10, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1703": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2018, 10, 9, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2019, 10, 8, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1709": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2020, 10, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1803": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2019, 11, 12, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1809": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2020, 11, 10, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1903": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 12, 8, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 1909": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2022, 5, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 2004": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2021, 12, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 20H2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2022, 5, 10, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2023, 5, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 21H1": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 12, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 21H2": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2023, 6, 13, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2024, 6, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 10 Version 22H2": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 11 Version 21H2": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 11 Version 22H2": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows 11 Version 23H2": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard(Home and Pro)":             time.Date(2025, 11, 11, 23, 59, 59, 0, time.UTC),
				"Standard(Enterprise and Education)": time.Date(2026, 11, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2003": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard":       time.Date(2007, 4, 10, 23, 59, 59, 0, time.UTC),
				"Service Pack 1": time.Date(2009, 4, 14, 23, 59, 59, 0, time.UTC),
				"Service Pack 2": time.Date(2015, 7, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2003 R2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard":       time.Date(2009, 4, 14, 23, 59, 59, 0, time.UTC),
				"Service Pack 2": time.Date(2015, 7, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2008": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard":                                     time.Date(2011, 7, 12, 23, 59, 59, 0, time.UTC),
				"Service Pack 2":                               time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 1":              time.Date(2021, 1, 12, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 2":              time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 3":              time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 4 (Azure only)": time.Date(2024, 1, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2008 R2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard":                                     time.Date(2013, 4, 9, 23, 59, 59, 0, time.UTC),
				"Service Pack 1":                               time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 1":              time.Date(2021, 1, 12, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 2":              time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 3":              time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 4 (Azure only)": time.Date(2024, 1, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2012": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard":                        time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 1": time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 2": time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 3": time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2012 R2": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard":                        time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 1": time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 2": time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC),
				"Extended Security Update Year 3": time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2016": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 1, 11, 23, 59, 59, 0, time.UTC),
				"ESU":      time.Date(2027, 1, 12, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server, Version 1709": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server, Version 1803": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2019, 11, 12, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server, Version 1809": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 11, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2019": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2024, 1, 9, 23, 59, 59, 0, time.UTC),
				"ESU":      time.Date(2029, 1, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server, Version 1903": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2020, 12, 8, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server, Version 1909": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server, Version 2004": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2021, 12, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server, Version 20H2": {
			Ended: true,
			Date: map[string]time.Time{
				"Standard": time.Date(2022, 8, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"Windows Server 2022": {
			Ended: false,
			Date: map[string]time.Time{
				"Standard": time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC),
				"ESU":      time.Date(2031, 10, 14, 23, 59, 59, 0, time.UTC),
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
			Date:  map[string]time.Time{"Standard": time.Date(2016, 12, 1, 23, 59, 59, 0, time.UTC)},
		},
		"10.10": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2017, 8, 1, 23, 59, 59, 0, time.UTC)},
		},
		"10.11": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2018, 12, 1, 23, 59, 59, 0, time.UTC)},
		},
		"10.12": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2019, 10, 1, 23, 59, 59, 0, time.UTC)},
		},
		"10.13": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2020, 12, 1, 23, 59, 59, 0, time.UTC)},
		},
		"10.14": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2021, 10, 25, 23, 59, 59, 0, time.UTC)},
		},
		"10.15": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2022, 9, 12, 23, 59, 59, 0, time.UTC)},
		},
		"11": {
			Ended: true,
			Date:  map[string]time.Time{"Standard": time.Date(2023, 9, 26, 23, 59, 59, 0, time.UTC)},
		},
		"12": {Ended: false},
		"13": {Ended: false},
		"14": {Ended: false},
	},
	ecosystemTypes.EcosystemTypeFortinet: {
		"FortiOS 4.2": {
			Ended: true,
		},
		"FortiOS 5.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2018, 12, 21, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2020, 6, 21, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiOS 5.6": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 3, 30, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiOS 6.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 3, 29, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 9, 29, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiOS 6.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 3, 28, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 9, 28, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiOS 6.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 3, 31, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 9, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiOS 7.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2024, 3, 30, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2025, 9, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiOS 7.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 3, 31, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiOS 7.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2026, 5, 11, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2027, 11, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 5.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2017, 9, 4, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2019, 3, 4, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 5.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2019, 2, 17, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2020, 8, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 5.6": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 7, 27, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 1, 27, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 6.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 4, 18, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 10, 18, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 6.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 4, 11, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 10, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 6.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 4, 9, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 10, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 7.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2024, 4, 22, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2025, 10, 22, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 7.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 4, 11, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 10, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAnalyzer 7.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2026, 5, 15, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2027, 11, 15, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 5.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2017, 8, 25, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2019, 2, 25, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 5.3": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2018, 11, 30, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2020, 5, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 5.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 7, 25, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 1, 25, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 6.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 5, 29, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 11, 29, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 6.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 8, 9, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 2, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 6.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 5, 8, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 11, 8, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 7.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2024, 5, 17, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2025, 11, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiMail 7.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 5, 10, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 11, 10, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 5.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2017, 8, 23, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2019, 2, 23, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 5.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2019, 2, 17, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2020, 8, 17, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 5.6": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 7, 27, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 1, 27, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 6.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 4, 18, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 10, 18, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 6.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 4, 11, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 10, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 6.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 4, 9, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 10, 9, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 7.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2024, 4, 22, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2025, 10, 22, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiManager 7.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 4, 11, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 10, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 5.6": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2019, 9, 26, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2019, 9, 26, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 5.7": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 1, 18, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2021, 7, 18, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 5.8": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 4, 27, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2021, 10, 27, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 5.9": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 3, 20, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 9, 20, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 6.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 5, 23, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 11, 23, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 6.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 3, 27, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 9, 27, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 6.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 9, 30, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 3, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 6.3": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 1, 21, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 7, 21, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 6.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 4, 1, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 10, 1, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 7.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 1, 19, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 7, 19, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiWeb 7.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 1, 16, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2027, 6, 16, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAP 5.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2019, 1, 8, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2020, 7, 8, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAP 5.6": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 4, 13, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2021, 10, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAP 6.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 4, 11, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 10, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAP 6.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 4, 14, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 10, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAP 6.4": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 4, 14, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 10, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAP 7.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2024, 4, 20, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2025, 10, 20, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiAP 7.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 4, 14, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 10, 14, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiSandbox 2.4": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 5, 3, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2021, 11, 3, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiSandbox 2.5": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2020, 11, 2, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 5, 2, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiSandbox 3.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 7, 31, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 1, 31, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiSandbox 3.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 6, 18, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 12, 18, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiSandbox 3.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 4, 30, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2024, 10, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiSandbox 4.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2024, 4, 19, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2025, 10, 19, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiSandbox 4.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 4, 13, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiProxy 1.0": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 4, 11, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2022, 10, 11, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiProxy 1.1": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2021, 12, 22, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 6, 22, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiProxy 1.2": {
			Ended: true,
			Date: map[string]time.Time{
				"Full": time.Date(2022, 1, 30, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2023, 7, 30, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiProxy 2.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2023, 11, 15, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2025, 5, 15, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiProxy 7.0": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2024, 8, 24, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2026, 2, 24, 23, 59, 59, 0, time.UTC),
			},
		},
		"FortiProxy 7.2": {
			Ended: false,
			Date: map[string]time.Time{
				"Full": time.Date(2025, 9, 20, 23, 59, 59, 0, time.UTC),
				"EOS":  time.Date(2027, 3, 20, 23, 59, 59, 0, time.UTC),
			},
		},
	},
}
