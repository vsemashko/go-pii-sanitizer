package sanitizer

import (
	"regexp"
	"strconv"
	"strings"
)

// validateKoreanRRN validates a South Korean RRN (Resident Registration Number)
// Format: YYMMDD-GXXXXXX (13 digits)
//   YYMMDD: Date of birth
//   G: Gender/century digit (1-4)
//     1: Male born 1900-1999
//     2: Female born 1900-1999
//     3: Male born 2000-2099
//     4: Female born 2000-2099
//   XXXXXX: Birthplace and sequence + check digit
func validateKoreanRRN(rrn string) bool {
	// Remove dashes
	rrn = strings.ReplaceAll(rrn, "-", "")

	if len(rrn) != 13 {
		return false
	}

	// Check all characters are digits
	for _, c := range rrn {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Validate date portion (YYMMDD)
	month, err := strconv.Atoi(rrn[2:4])
	if err != nil || month < 1 || month > 12 {
		return false
	}

	day, err := strconv.Atoi(rrn[4:6])
	if err != nil || day < 1 || day > 31 {
		return false
	}

	// Validate gender/century digit
	genderDigit, err := strconv.Atoi(string(rrn[6]))
	if err != nil || genderDigit < 1 || genderDigit > 4 {
		return false
	}

	// Validate checksum (last digit)
	// Algorithm: weighted sum with weights [2,3,4,5,6,7,8,9,2,3,4,5]
	weights := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for i := 0; i < 12; i++ {
		digit, _ := strconv.Atoi(string(rrn[i]))
		sum += digit * weights[i]
	}

	checkDigit := (11 - (sum % 11)) % 10
	expectedDigit, _ := strconv.Atoi(string(rrn[12]))

	return checkDigit == expectedDigit
}

// getSouthKoreaPatterns returns PII patterns for South Korea
func getSouthKoreaPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: SouthKorea,
		FieldNames: []string{
			"rrn", "residentRegistrationNumber", "resident_registration_number",
			"koreanId", "korean_id", "nationalId", "national_id",
			"jumin", "juminNumber", "jumin_number",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "southkorea_rrn",
				// Format: YYMMDD-GXXXXXX (13 digits)
				Pattern:   regexp.MustCompile(`\b\d{6}-[1-4]\d{6}\b`),
				Validator: validateKoreanRRN, // Checksum validation
			},
			{
				Name: "southkorea_phone",
				// Phone: +82 or 0 followed by area/mobile code and number
				// Mobile: 010-xxxx-xxxx (11 digits total with dashes)
				Pattern: regexp.MustCompile(`(?:\+82|82|0)10-?\d{4}-?\d{4}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
		},
	}
}
