package sanitizer

import "regexp"

// getUAEPatterns returns PII patterns for UAE
func getUAEPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: UAE,
		FieldNames: []string{
			"emiratesId", "emirates_id", "eid", "uaeId",
			"identityCard", "identity_card", "nationalId",
			"iban", "accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "uae_emirates_id",
				// Format: 784-YYYY-XXXXXXX-X (15 digits)
				// Often written without dashes: 784YYYYXXXXXXXD
				Pattern: regexp.MustCompile(`\b784-?\d{4}-?\d{7}-?\d\b`),
			},
			{
				Name: "uae_phone",
				// Phone: +971 or 00971 or 0 + area/mobile code + 7 digits
				Pattern: regexp.MustCompile(`(?:\+971|00971|0)(?:2|3|4|6|7|9|50|51|52|54|55|56|58)\d{7}\b`),
			},
			{
				Name: "uae_iban",
				// IBAN: AE + 2 check digits + 19 digits (23 chars total)
				// Format: AE07 0331 2345 6789 0123 456
				// This pattern is specific enough to avoid false positives
				Pattern: regexp.MustCompile(`\bAE\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{3}\b`),
			},
			// NOTE: Generic bank account patterns omitted - use field name matching only
		},
	}
}
