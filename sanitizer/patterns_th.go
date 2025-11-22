package sanitizer

import (
	"regexp"
	"strings"
)

// validateThaiID validates Thailand National ID checksum using modulo 11 algorithm
// Format: X-XXXX-XXXXX-XX-X (13 digits total)
// The last digit is a check digit calculated using modulo 11
func validateThaiID(id string) bool {
	// Remove dashes
	cleaned := strings.ReplaceAll(id, "-", "")

	// Must be exactly 13 digits
	if len(cleaned) != 13 {
		return false
	}

	// Verify all characters are digits
	for _, c := range cleaned {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Calculate checksum using modulo 11 algorithm
	// Multiply first 12 digits by (13 - position), sum them
	sum := 0
	for i := 0; i < 12; i++ {
		digit := int(cleaned[i] - '0')
		weight := 13 - i
		sum += digit * weight
	}

	// Check digit = (11 - (sum mod 11)) mod 10
	expectedCheckDigit := (11 - (sum % 11)) % 10
	actualCheckDigit := int(cleaned[12] - '0')

	return expectedCheckDigit == actualCheckDigit
}

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
				// Uses modulo 11 checksum validation to reduce false positives
				Pattern:   regexp.MustCompile(`\b\d-?\d{4}-?\d{5}-?\d{2}-?\d\b`),
				Validator: validateThaiID,
			},
			{
				Name: "thailand_phone",
				// Phone: +66 followed by 8-9 digits (mobile: 6/8/9 prefix)
				Pattern: regexp.MustCompile(`(?:\+66|66|0)[689]\d{8}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
			// Pattern \b\d{10,12}\b would match timestamps, order IDs, product codes, etc.
			// Use field name matching only for bank accounts
		},
	}
}
