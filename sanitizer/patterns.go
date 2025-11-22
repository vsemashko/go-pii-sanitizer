package sanitizer

import "regexp"

// ContentPattern defines a pattern for detecting PII in field content
type ContentPattern struct {
	Name      string
	Pattern   *regexp.Regexp
	Validator func(string) bool // Optional validation function (e.g., Luhn for credit cards)
}

// RegionalPatterns holds all pattern definitions for a region
type RegionalPatterns struct {
	Region          Region
	FieldNames      []string
	ContentPatterns []ContentPattern
}

// getAllRegionalPatterns returns pattern definitions for all regions
func getAllRegionalPatterns() []RegionalPatterns {
	return []RegionalPatterns{
		getSingaporePatterns(),
		getMalaysiaPatterns(),
		getUAEPatterns(),
		getThailandPatterns(),
		getHongKongPatterns(),
		getIndonesiaPatterns(),
		getPhilippinesPatterns(),
		getVietnamPatterns(),
		getSouthKoreaPatterns(),
	}
}
