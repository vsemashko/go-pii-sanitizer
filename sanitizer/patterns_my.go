package sanitizer

import (
	"regexp"
	"strconv"
	"strings"
)

// validateMyKad validates Malaysia MyKad date portion
func validateMyKad(mykad string) bool {
	// Remove dashes
	mykad = strings.ReplaceAll(mykad, "-", "")

	if len(mykad) != 12 {
		return false
	}

	// Extract date portion (YYMMDD)
	yearStr := mykad[0:2]
	monthStr := mykad[2:4]
	dayStr := mykad[4:6]

	year, err := strconv.Atoi(yearStr)
	if err != nil {
		return false
	}

	month, err := strconv.Atoi(monthStr)
	if err != nil || month < 1 || month > 12 {
		return false
	}

	day, err := strconv.Atoi(dayStr)
	if err != nil || day < 1 || day > 31 {
		return false
	}

	// Basic month validation (simplified - doesn't check leap years)
	daysInMonth := map[int]int{
		1: 31, 2: 29, 3: 31, 4: 30, 5: 31, 6: 30,
		7: 31, 8: 31, 9: 30, 10: 31, 11: 30, 12: 31,
	}

	if day > daysInMonth[month] {
		return false
	}

	// Year must be reasonable (00-99 representing 1900-2099)
	// Most MyKad holders are born between 1900-2024
	_ = year // Year validation is lenient

	return true
}

// getMalaysiaPatterns returns PII patterns for Malaysia
func getMalaysiaPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: Malaysia,
		FieldNames: []string{
			"mykad", "ic", "icNumber", "myKadNumber",
			"identityCard", "identity_card", "malaysianId",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "malaysia_mykad",
				// Format: YYMMDD-BP-NNNG (12 digits with dashes)
				// Or: YYMMDDBBNNNG (12 digits without dashes)
				Pattern:   regexp.MustCompile(`\b\d{6}-?\d{2}-?\d{4}\b`),
				Validator: validateMyKad,
			},
			{
				Name: "malaysia_phone",
				// Phone: +60 / 60 / 0 + prefix + number
				// 01X-XXX-XXXX or 01X-XXXXXXXX (depending on prefix)
				Pattern: regexp.MustCompile(`(?:\+?60|0)1[0-46-9]\d{7,8}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
			// Bank accounts are now detected ONLY via field name matching
			// This prevents matching any 7-16 digit number (order IDs, product codes, etc.)
		},
	}
}
