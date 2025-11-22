package sanitizer

import "regexp"

// getCommonFieldNames returns field name patterns for common PII types
// Priority order based on user requirements
func getCommonFieldNames() map[string][]string {
	return map[string][]string{
		// PRIORITY 1: Legal names - highest priority
		"name": {
			"fullName", "full_name", "legalName", "legal_name",
			"firstName", "first_name", "lastName", "last_name",
			"surname", "givenName", "given_name", "customerName", "customer_name",
			"userName", "user_name", "displayName", "display_name",
		},

		// PRIORITY 2: Transaction descriptions - often contains PII
		"transaction": {
			"description", "transactionDescription", "transaction_description",
			"memo", "narrative", "reference", "remarks", "notes",
			"paymentReference", "payment_reference", "transferDetails",
		},

		// PRIORITY 3: Bank account numbers (regional patterns above)
		"bankAccount": {
			"accountNumber", "account_number", "bankAccount", "bank_account",
			"iban", "accountNo", "account_no", "beneficiaryAccount",
		},

		// PRIORITY 4: Email addresses
		"email": {
			"email", "e_mail", "emailAddress", "email_address", "mail",
			"userEmail", "user_email", "contactEmail", "contact_email",
		},

		// PRIORITY 5: Physical addresses
		"address": {
			"address", "street", "streetAddress", "street_address",
			"homeAddress", "home_address", "billingAddress", "billing_address",
			"shippingAddress", "shipping_address", "mailingAddress", "mailing_address",
			"postalCode", "postal_code", "postCode", "post_code", "zipCode", "zip_code",
			"city", "state", "province", "country",
		},

		// Other common PII
		"phone": {
			"phone", "phoneNumber", "phone_number", "mobile", "mobileNumber",
			"telephone", "tel", "contact", "contactNumber", "contact_number",
		},
		"passport": {
			"passport", "passportNumber", "passport_number", "passportNo",
		},
		"dob": {
			"dateOfBirth", "date_of_birth", "dob", "birthDate", "birth_date",
			"birthday",
		},
		"creditCard": {
			"creditCard", "credit_card", "cardNumber", "card_number",
			"ccNumber", "cc_number", "paymentCard", "payment_card",
		},
	}
}

// getSecretFieldNames returns field names that should always be redacted
func getSecretFieldNames() []string {
	return []string{
		"password", "passwd", "pwd", "secret",
		"token", "accessToken", "access_token", "refreshToken", "refresh_token",
		"apiKey", "api_key", "apiSecret", "api_secret",
		"privateKey", "private_key", "secretKey", "secret_key",
		"credential", "credentials", "auth", "authorization",
		"bearer", "sessionId", "session_id", "otp", "pin",
	}
}

// getCommonContentPatterns returns content patterns for common PII types
func getCommonContentPatterns() []ContentPattern {
	return []ContentPattern{
		{
			Name: "email",
			// RFC 5322 simplified with Unicode support (IDN - Internationalized Domain Names)
			// Supports emails like: user@example.com, 用户@例え.jp, пользователь@пример.рф
			// \p{L} matches any Unicode letter, \p{N} matches any Unicode number
			Pattern: regexp.MustCompile(`\b[\p{L}\p{N}._%+-]+@[\p{L}\p{N}.-]+\.[\p{L}]{2,}\b`),
		},
		{
			Name:    "credit_card",
			Pattern: regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{0,3}\b`),
			// Luhn validation enabled to reduce false positives on order numbers, tracking codes, etc.
			// Only matches valid credit card numbers (Visa, Mastercard, Amex, Discover, etc.)
			Validator: validateLuhn,
		},
		// NOTE: IPv4/IPv6 patterns removed from default PII detection
		// IP addresses are rarely considered PII under GDPR/PDPA
		// They often cause false positives on version numbers (1.2.3.4), configuration, etc.
		// If you need IP detection, add custom patterns via config.CustomContentPatterns
	}
}

// validateLuhn validates a credit card number using the Luhn algorithm
func validateLuhn(cardNumber string) bool {
	// Remove spaces, dashes, and any non-digit characters
	var digits []int
	for _, r := range cardNumber {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}

	// Credit cards are typically 13-19 digits
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	// Luhn algorithm: start from rightmost digit (check digit)
	sum := 0
	parity := len(digits) % 2

	for i := 0; i < len(digits); i++ {
		digit := digits[i]

		// Double every second digit (from right to left, so based on parity)
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
	}

	return sum%10 == 0
}
