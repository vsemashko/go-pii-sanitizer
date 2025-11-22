package sanitizer

import (
	"regexp"
	"strconv"
	"strings"
)

// validateIndonesianNIK validates an Indonesian NIK (Nomor Induk Kependudukan)
// Format: PPKKSSDDMMYYXXXX (16 digits)
//   PP: Province code (01-99)
//   KK: Regency/city code
//   SS: Subdistrict code
//   DDMMYY: Date of birth (DD: 01-31, MM: 01-12, YY: year)
//   XXXX: Unique sequence
func validateIndonesianNIK(nik string) bool {
	// Remove any spaces or dashes
	nik = strings.ReplaceAll(strings.ReplaceAll(nik, "-", ""), " ", "")

	if len(nik) != 16 {
		return false
	}

	// Check all characters are digits
	for _, c := range nik {
		if c < '0' || c > '9' {
			return false
		}
	}

	// Validate date portion (positions 6-11: DDMMYY)
	day, err := strconv.Atoi(nik[6:8])
	if err != nil || day < 1 || day > 31 {
		return false
	}

	month, err := strconv.Atoi(nik[8:10])
	if err != nil || month < 1 || month > 12 {
		return false
	}

	// Basic day-per-month validation
	daysInMonth := map[int]int{
		1: 31, 2: 29, 3: 31, 4: 30, 5: 31, 6: 30,
		7: 31, 8: 31, 9: 30, 10: 31, 11: 30, 12: 31,
	}

	if day > daysInMonth[month] {
		return false
	}

	return true
}

// getIndonesiaPatterns returns PII patterns for Indonesia
func getIndonesiaPatterns() RegionalPatterns {
	return RegionalPatterns{
		Region: Indonesia,
		FieldNames: []string{
			"nik", "nomor_induk", "nomorInduk", "identitas",
			"ktp", "identityCard", "identity_card", "indonesianId",
			"accountNumber", "account_number", "bankAccount", "bank_account",
		},
		ContentPatterns: []ContentPattern{
			{
				Name: "indonesia_nik",
				// Format: 16 digits (PPKKSSDDMMYYXXXX)
				Pattern:   regexp.MustCompile(`\b\d{16}\b`),
				Validator: validateIndonesianNIK, // Date validation
			},
			{
				Name: "indonesia_phone",
				// Phone: +62 or 0 followed by area code and number
				// Mobile: 08xx-xxxx-xxxx (10-12 digits total)
				Pattern: regexp.MustCompile(`(?:\+62|62|0)8\d{8,10}\b`),
			},
			// NOTE: Bank account content pattern removed to prevent false positives
		},
	}
}
