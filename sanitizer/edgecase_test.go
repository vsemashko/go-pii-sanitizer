package sanitizer

import (
	"strings"
	"testing"
)

// Additional edge case tests

func TestEmptyValues(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name      string
		fieldName string
		value     string
		expected  string
	}{
		{"Empty string", "email", "", ""},
		{"Empty field name", "", "value", "value"},
		{"Both empty", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField(tt.fieldName, tt.value)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestCaseInsensitiveFieldNames(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		fieldName string
		value     string
	}{
		{"email", "user@example.com"},
		{"Email", "user@example.com"},
		{"EMAIL", "user@example.com"},
		{"eMaIl", "user@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			result := s.SanitizeField(tt.fieldName, tt.value)
			if result == tt.value {
				t.Errorf("Expected %s to be redacted regardless of case", tt.fieldName)
			}
		})
	}
}

func TestMultiplePIIInSingleValue(t *testing.T) {
	s := NewDefault()

	text := "Contact John Doe at john@example.com or +6591234567 for NRIC S1234567D"
	result := s.SanitizeField("description", text)

	// Should be redacted because it contains multiple PII patterns
	if result == text {
		t.Error("Expected text with multiple PII to be redacted")
	}
}

func TestLongNestedStructure(t *testing.T) {
	s := NewDefault()

	// Create deeply nested structure
	data := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": map[string]any{
					"level4": map[string]any{
						"level5": map[string]any{
							"email": "user@example.com",
						},
					},
				},
			},
		},
	}

	result := s.SanitizeMap(data)

	// Navigate to deepest level
	l1 := result["level1"].(map[string]any)
	l2 := l1["level2"].(map[string]any)
	l3 := l2["level3"].(map[string]any)
	l4 := l3["level4"].(map[string]any)
	l5 := l4["level5"].(map[string]any)

	if l5["email"] == "user@example.com" {
		t.Error("Expected deeply nested email to be redacted")
	}
}

func TestSliceOfMaps(t *testing.T) {
	s := NewDefault()

	data := map[string]any{
		"users": []any{
			map[string]any{
				"email": "user1@example.com",
				"name":  "User One",
			},
			map[string]any{
				"email": "user2@example.com",
				"name":  "User Two",
			},
		},
	}

	result := s.SanitizeMap(data)
	users := result["users"].([]any)

	user1 := users[0].(map[string]any)
	if user1["email"] == "user1@example.com" {
		t.Error("Expected email in slice to be redacted")
	}

	user2 := users[1].(map[string]any)
	if user2["email"] == "user2@example.com" {
		t.Error("Expected email in slice to be redacted")
	}
}

func TestSliceOfStrings(t *testing.T) {
	s := NewDefault()

	data := map[string]any{
		"emails": []any{
			"user1@example.com",
			"user2@example.com",
			"not-an-email",
		},
	}

	result := s.SanitizeMap(data)
	emails := result["emails"].([]any)

	// Email patterns in slice content should be detected
	if emails[0] == "user1@example.com" {
		t.Error("Expected email in string slice to be redacted")
	}
	if emails[1] == "user2@example.com" {
		t.Error("Expected email in string slice to be redacted")
	}
	if emails[2] != "not-an-email" {
		t.Error("Expected non-email to be preserved")
	}
}

func TestMixedTypes(t *testing.T) {
	s := NewDefault()

	data := map[string]any{
		"string":  "user@example.com",
		"int":     12345,
		"float":   99.99,
		"bool":    true,
		"null":    nil,
		"orderId": "ORD-123",
	}

	result := s.SanitizeMap(data)

	// String with PII should be redacted
	if result["string"] == "user@example.com" {
		t.Error("Expected email string to be redacted")
	}

	// Non-string types should be preserved
	if result["int"] != 12345 {
		t.Error("Expected int to be preserved")
	}
	if result["float"] != 99.99 {
		t.Error("Expected float to be preserved")
	}
	if result["bool"] != true {
		t.Error("Expected bool to be preserved")
	}
	if result["null"] != nil {
		t.Error("Expected nil to be preserved")
	}
	if result["orderId"] != "ORD-123" {
		t.Error("Expected non-PII string to be preserved")
	}
}

func TestExplicitListPriority(t *testing.T) {
	config := NewDefaultConfig().
		WithRedact("orderId"). // Normally not PII
		WithPreserve("email")  // Override email pattern

	s := New(config)

	// orderId should be redacted even though it's not a PII pattern
	result := s.SanitizeField("orderId", "ORD-123")
	if result != "[REDACTED]" {
		t.Errorf("Expected orderId to be redacted via AlwaysRedact, got: %s", result)
	}

	// email should be preserved even though it matches pattern
	result = s.SanitizeField("email", "user@example.com")
	if result != "user@example.com" {
		t.Errorf("Expected email to be preserved via NeverRedact, got: %s", result)
	}
}

func TestAllRegions(t *testing.T) {
	s := NewDefault() // All regions enabled

	tests := []struct {
		name  string
		value string
	}{
		{"Singapore NRIC", "S1234567D"},
		{"Malaysia MyKad", "901230-14-5678"},
		{"UAE Emirates ID", "784-2020-1234567-1"},
		{"Thailand ID", "1-2345-67890-12-1"},
		{"Hong Kong HKID", "A123456(7)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField("text", tt.value)
			if result == tt.value {
				t.Errorf("Expected %s to be redacted", tt.name)
			}
		})
	}
}

func TestSingleRegion(t *testing.T) {
	s := NewForRegion(Singapore)

	// Singapore NRIC should be detected
	result := s.SanitizeField("text", "S1234567D")
	if result == "S1234567D" {
		t.Error("Expected Singapore NRIC to be redacted")
	}

	// Malaysia MyKad should NOT be detected (region not enabled)
	result = s.SanitizeField("text", "901230-14-5678")
	if result != "901230-14-5678" {
		t.Error("Expected Malaysia MyKad to be preserved (region not enabled)")
	}
}

func TestJSONWithUnicodeAndSpecialChars(t *testing.T) {
	s := NewDefault()

	jsonData := []byte(`{
		"email": "user@example.com",
		"name": "José María",
		"description": "Payment with emoji 💰",
		"amount": 100.50
	}`)

	result, err := s.SanitizeJSON(jsonData)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	resultStr := string(result)
	if strings.Contains(resultStr, "user@example.com") {
		t.Error("Expected email to be redacted in JSON")
	}

	// Should still parse as valid JSON
	if !strings.Contains(resultStr, "José María") && !strings.Contains(resultStr, "[REDACTED]") {
		t.Error("Expected name to be either preserved or redacted")
	}
}

func TestTransactionDescriptionFields(t *testing.T) {
	s := NewDefault()

	transactionFields := []string{
		"description",
		"transactionDescription",
		"memo",
		"narrative",
		"reference",
		"remarks",
		"notes",
	}

	for _, field := range transactionFields {
		t.Run(field, func(t *testing.T) {
			result := s.SanitizeField(field, "Payment to vendor")
			if result == "Payment to vendor" {
				t.Errorf("Expected transaction field %s to be redacted", field)
			}
		})
	}
}

func TestBankAccountFields(t *testing.T) {
	s := NewDefault()

	accountFields := []string{
		"accountNumber",
		"account_number",
		"bankAccount",
		"bank_account",
		"iban",
	}

	for _, field := range accountFields {
		t.Run(field, func(t *testing.T) {
			result := s.SanitizeField(field, "1234567890")
			if result == "1234567890" {
				t.Errorf("Expected account field %s to be redacted", field)
			}
		})
	}
}

// TestIPAddressDetection removed - IP addresses are no longer detected by default
// Rationale: IPs rarely qualify as PII under GDPR/PDPA and caused false positives
// on version numbers (1.2.3.4), configuration values, etc.
// Users can add IP detection via config.CustomContentPatterns if needed

func TestPhoneNumberVariations(t *testing.T) {
	s := NewForRegion(Singapore, Malaysia, UAE, Thailand, HongKong)

	tests := []struct {
		region string
		phone  string
	}{
		{"Singapore", "+6591234567"},
		{"Singapore", "6591234567"},
		{"Singapore", "91234567"},
		{"Malaysia", "+60123456789"},
		{"Malaysia", "0123456789"},
		{"UAE", "+971501234567"},
		{"UAE", "0501234567"},
		{"Thailand", "+66812345678"},
		{"Thailand", "0812345678"},
		{"Hong Kong", "+85291234567"},
		{"Hong Kong", "91234567"},
	}

	for _, tt := range tests {
		t.Run(tt.region+"_"+tt.phone, func(t *testing.T) {
			result := s.SanitizeField("phone", tt.phone)
			if result == tt.phone {
				t.Errorf("Expected %s phone %s to be redacted", tt.region, tt.phone)
			}
		})
	}
}
