package sanitizer

import "regexp"

// getSingaporePatterns returns PII patterns for Singapore
func getSingaporePatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: Singapore,
		FieldNames: []string{
			"nric", "ic", "identityCard", "identity_card",
			"fin", "foreignId", "foreign_id",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "singapore_nric",
				// Format: [STFGM]1234567A (prefix + 7 digits + checksum)
				Pattern: regexp.MustCompile(`(?i)\b[STFGM]\d{7}[A-Z]\b`),
			},
			{
				Name: "singapore_fin",
				// Foreign Identification Number
				Pattern: regexp.MustCompile(`(?i)\b[FGM]\d{7}[A-Z]\b`),
			},
			{
				Name: "singapore_phone",
				// Phone: +65 [689]XXXXXXX (8 digits total)
				Pattern: regexp.MustCompile(`(?:\+65|65)?[689]\d{7}\b`),
			},
			{
				Name: "singapore_bank_account",
				// Bank Account: 7-11 digits (with or without bank/branch codes)
				// Full format: BBBB-BBB-AAAAAAAAAA (bank code-branch-account)
				Pattern: regexp.MustCompile(`\b\d{4}-\d{3}-\d{7,11}\b|\b\d{7,11}\b`),
			},
		},
	}
}
