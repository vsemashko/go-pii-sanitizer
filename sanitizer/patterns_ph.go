package sanitizer

import "regexp"

// getPhilippinesPatterns returns PII patterns for Philippines
func getPhilippinesPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: Philippines,
		FieldNames: []string{
			"philsysId", "philsys_id", "psa", "psaId", "psa_id",
			"nationalId", "national_id", "philippineId",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "philippines_philsys_id",
				// Format: XXXX-XXXX-XXXX-XXXX (16 digits with dashes)
				Pattern: regexp.MustCompile(`\b\d{4}-\d{4}-\d{4}-\d{4}\b`),
			},
			{
				Name: "philippines_phone",
				// Phone: +63 or 0 followed by area/mobile code and number
				// Mobile: 09xx-xxx-xxxx (11 digits total)
				Pattern: regexp.MustCompile(`(?:\+63|63|0)9\d{9}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
		},
	}
}
