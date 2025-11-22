package sanitizer

import "regexp"

// getVietnamPatterns returns PII patterns for Vietnam
func getVietnamPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: Vietnam,
		FieldNames: []string{
			"cccd", "cmnd", "nationalId", "national_id",
			"vietnamId", "vietnam_id", "identityCard", "identity_card",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "vietnam_cccd",
				// CCCD (Căn cước công dân) - 12 digits (new format)
				// CMND (Chứng minh nhân dân) - 9 or 12 digits (old format)
				Pattern: regexp.MustCompile(`\b\d{12}\b|\b\d{9}\b`),
			},
			{
				Name: "vietnam_phone",
				// Phone: +84 or 0 followed by area/mobile code and number
				// Mobile: 09x, 08x, 07x, 05x, 03x (10 digits total)
				Pattern: regexp.MustCompile(`(?:\+84|84|0)[0-9]\d{8}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
		},
	}
}
