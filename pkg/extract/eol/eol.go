package eol

import (
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

type options struct {
	dir string
}

type Option interface {
	apply(*options)
}

type dirOption string

func (d dirOption) apply(opts *options) {
	opts.dir = string(d)
}

func WithDir(dir string) Option {
	return dirOption(dir)
}

var eols = map[string]map[string]types.EOLDictionary{
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
				"Full":         {},
				"Maintenance1": {},
				"Maintenance2": {},
				"ELS":          {},
				"ELP":          {},
			},
		},
		"4": {
			Ended: true,
			Date: map[string]*time.Time{
				"Full":         {},
				"Maintenance1": {},
				"Maintenance2": {},
				"ELS":          {},
				"ELP":          {},
			},
		},
		"5": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         {},
				"Maintenance1": {},
				"Maintenance2": {},
				"ELS":          {},
				"ELP":          nil,
			},
		},
		"6": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         {},
				"Maintenance1": {},
				"Maintenance2": {},
				"ELS":          {},
				"ELP":          nil,
			},
		},
		"7": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         {},
				"Maintenance1": {},
				"Maintenance2": {},
				"ELS":          {},
				"ELP":          nil,
			},
		},
		"8": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         {},
				"Maintenance1": {},
				"Maintenance2": {},
				"ELS":          {},
				"ELP":          nil,
			},
		},
		"9": {
			Ended: false,
			Date: map[string]*time.Time{
				"Full":         {},
				"Maintenance1": {},
				"Maintenance2": {},
				"ELS":          {},
				"ELP":          nil,
			},
		},
	},
	detection.EcosystemTypeRocky:       {},
	detection.EcosystemTypeOpenSUSE:    {},
	detection.EcosystemTypeSUSEServer:  {},
	detection.EcosystemTypeSUSEDesktop: {},
	detection.EcosystemTypeUbuntu:      {},
	detection.EcosystemTypeWindows:     {},

	detection.EcosystemTypeFortinet: {},
}

func Extract(opts ...Option) error {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "extract", "eol"),
	}

	for _, o := range opts {
		o.apply(options)
	}

	if err := util.RemoveAll(options.dir); err != nil {
		return errors.Wrapf(err, "remove %s", options.dir)
	}

	log.Printf("[INFO] Extract End of Life")
	now := time.Now().UTC()
	for e, m := range eols {
		for v, eol := range m {
			if !eol.Ended {
				ds := maps.Values(eol.Date)
				if slices.Contains(ds, nil) {
					continue
				}

				slices.SortFunc(ds, func(i, j *time.Time) int {
					if (*i).Before(*j) {
						return -1
					}
					if (*i).Equal(*j) {
						return 0
					}
					return 1
				})
				if now.After(*ds[len(ds)-1]) {
					eol.Ended = true
				}
			}
			m[v] = eol
		}

		if err := util.Write(filepath.Join(options.dir, fmt.Sprintf("%s.json", e)), m); err != nil {
			return errors.Wrapf(err, "write %s", filepath.Join(options.dir, fmt.Sprintf("%s.json", e)))
		}
	}

	return nil
}
