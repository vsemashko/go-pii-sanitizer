package sanitizer

import "regexp"

// getThailandPatterns returns PII patterns for Thailand
func getThailandPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: Thailand,
		FieldNames: []string{
			"thaiId", "thai_id", "nationalId", "national_id",
			"idCard", "id_card", "citizenId",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "thailand_national_id",
				// Format: 13 digits (X-XXXX-XXXXX-XX-X with check digit)
				Pattern: regexp.MustCompile(`\b\d-?\d{4}-?\d{5}-?\d{2}-?\d\b`),
			},
			{
				Name: "thailand_phone",
				// Phone: +66 followed by 8-9 digits (mobile: 6/8/9 prefix)
				Pattern: regexp.MustCompile(`(?:\+66|66|0)[689]\d{8}\b`),
			},
			{
				Name: "thailand_bank_account",
				// Bank Account: Usually 10 digits (format: 012-3-45678-9)
				// Format varies by bank, but 10 digits is standard
				Pattern: regexp.MustCompile(`\b\d{3}-?\d-?\d{5}-?\d\b|\b\d{10,12}\b`),
			},
		},
	}
}
