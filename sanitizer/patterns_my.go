package sanitizer

import "regexp"

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
				Pattern: regexp.MustCompile(`\b\d{6}-?\d{2}-?\d{4}\b`),
			},
			{
				Name: "malaysia_phone",
				// Phone: +60 / 60 / 0 + prefix + number
				// 01X-XXX-XXXX or 01X-XXXXXXXX (depending on prefix)
				Pattern: regexp.MustCompile(`(?:\+?60|0)1[0-46-9]\d{7,8}\b`),
			},
			{
				Name: "malaysia_bank_account",
				// Bank Account: 7-16 digits (varies by bank)
				// Maybank/Affin: 12, Public Bank: 10, RHB: 14, etc.
				Pattern: regexp.MustCompile(`\b\d{7,16}\b`),
			},
		},
	}
}
