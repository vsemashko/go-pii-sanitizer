package sanitizer

import (
	"regexp"
	"strconv"
	"strings"
)

// validateThaiID validates a Thai National ID using mod-11 checksum algorithm
// Format: X-XXXX-XXXXX-XX-X (13 digits total)
// Algorithm:
//   1. Multiply each of the first 12 digits by (13 - position)
//   2. Sum all products
//   3. Calculate (11 - (sum mod 11)) mod 10
//   4. Compare with the 13th digit (check digit)
func validateThaiID(id string) bool {
	// Remove dashes
	id = strings.ReplaceAll(id, "-", "")

	if len(id) != 13 {
		return false
	}

	// Check all characters are digits
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Calculate checksum
	sum := 0
	for i := 0; i < 12; i++ {
		digit, _ := strconv.Atoi(string(id[i]))
		sum += digit * (13 - i)
	}

	checkDigit := (11 - (sum % 11)) % 10
	expectedDigit, _ := strconv.Atoi(string(id[12]))

	return checkDigit == expectedDigit
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
				Pattern:   regexp.MustCompile(`\b\d-?\d{4}-?\d{5}-?\d{2}-?\d\b`),
				Validator: validateThaiID, // Validate mod-11 checksum
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
