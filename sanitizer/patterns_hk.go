package sanitizer

import "regexp"

// getHongKongPatterns returns PII patterns for Hong Kong
func getHongKongPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: HongKong,
		FieldNames: []string{
			"hkid", "identityCard", "identity_card",
			"hongkongId", "hongkong_id",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "hongkong_hkid",
				// Format: A123456(D) - 1 or 2 letters + 6 digits + check digit (0-9 or A)
				Pattern: regexp.MustCompile(`(?i)\b[A-Z]{1,2}\d{6}\([A0-9]\)|\b[A-Z]{1,2}\d{6}[A0-9]\b`),
			},
			{
				Name: "hongkong_phone",
				// Phone: +852 followed by 8 digits (mobile: 5/6/9 prefix)
				Pattern: regexp.MustCompile(`(?:\+852|852)?[5-9]\d{7}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
			// Pattern \b\d{9,12}\b would match order IDs, transaction IDs, timestamps, etc.
			// Use field name matching only for bank accounts
		},
	}
}
