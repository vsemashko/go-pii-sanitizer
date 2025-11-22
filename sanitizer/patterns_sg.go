package sanitizer

import (
	"regexp"
	"strings"
)

// validateNRIC validates Singapore NRIC/FIN checksum
func validateNRIC(nric string) bool {
	nric = strings.ToUpper(nric)
	if len(nric) != 9 {
		return false
	}

	prefix := nric[0]
	digits := nric[1:8]
	checksum := nric[8]

	// Weight array
	weights := []int{2, 7, 6, 5, 4, 3, 2}

	// Calculate weighted sum
	sum := 0
	for i, weight := range weights {
		digit := int(digits[i] - '0')
		sum += digit * weight
	}

	// Add offset based on prefix
	if prefix == 'T' || prefix == 'G' {
		sum += 4
	}

	// Checksum tables
	stChecksums := "JZIHGFEDCBA"
	fgChecksums := "XWUTRQPNMLK"

	expectedChecksum := byte(0)
	remainder := sum % 11

	if prefix == 'S' || prefix == 'T' {
		expectedChecksum = stChecksums[remainder]
	} else if prefix == 'F' || prefix == 'G' {
		expectedChecksum = fgChecksums[remainder]
	} else if prefix == 'M' {
		// M prefix uses FG table
		expectedChecksum = fgChecksums[remainder]
	}

	return checksum == expectedChecksum
}

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
				Pattern:   regexp.MustCompile(`(?i)\b[STFGM]\d{7}[A-Z]\b`),
				Validator: validateNRIC,
			},
			{
				Name: "singapore_fin",
				// Foreign Identification Number (uses same checksum algorithm as NRIC)
				Pattern:   regexp.MustCompile(`(?i)\b[FGM]\d{7}[A-Z]\b`),
				Validator: validateNRIC,
			},
			{
				Name: "singapore_phone",
				// Phone: +65 [689]XXXXXXX (8 digits total)
				Pattern: regexp.MustCompile(`(?:\+65|65)?[689]\d{7}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
			// Bank accounts are now detected ONLY via field name matching
			// (accountNumber, account_number, bankAccount, bank_account, iban)
			// This prevents matching order IDs, transaction IDs, and other numeric identifiers
		},
	}
}
