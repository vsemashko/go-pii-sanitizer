package sanitizer

import (
	"encoding/json"
	"regexp"
	"testing"
)

// TestWithRegions tests the WithRegions configuration method
func TestWithRegions(t *testing.T) {
	config := NewDefaultConfig().WithRegions(Singapore, Malaysia)

	if len(config.Regions) != 2 {
		t.Errorf("Expected 2 regions, got %d", len(config.Regions))
	}

	if config.Regions[0] != Singapore {
		t.Error("Expected first region to be Singapore")
	}

	if config.Regions[1] != Malaysia {
		t.Error("Expected second region to be Malaysia")
	}
}

// TestMatchType tests the matchType method in matcher
func TestMatchType(t *testing.T) {
	s := NewDefault()

	// Test matchType for email
	fieldType := s.fieldMatcher.matchType("email")
	if fieldType == "" {
		t.Error("Expected matchType to return non-empty for email")
	}

	// Test matchType for unknown field
	fieldType = s.fieldMatcher.matchType("unknown_field_xyz")
	if fieldType != "" {
		t.Error("Expected matchType to return empty for unknown field")
	}
}

// TestContentMatchType tests content pattern matching with type detection
func TestContentMatchType(t *testing.T) {
	s := NewDefault()

	// Test email pattern type detection
	emailType := s.contentMatcher.matchType("user@example.com")
	if emailType != "email" {
		t.Errorf("Expected 'email' type, got '%s'", emailType)
	}

	// Test credit card pattern type detection
	ccType := s.contentMatcher.matchType("4532-1234-5678-9010")
	if ccType != "credit_card" {
		t.Errorf("Expected 'credit_card' type, got '%s'", ccType)
	}

	// Test Singapore NRIC type detection
	nricType := s.contentMatcher.matchType("S1234567A")
	if nricType != "singapore_nric" {
		t.Errorf("Expected 'singapore_nric' type, got '%s'", nricType)
	}

	// Test non-matching content
	noType := s.contentMatcher.matchType("just some regular text")
	if noType != "" {
		t.Errorf("Expected empty type for regular text, got '%s'", noType)
	}
}

// TestSanitizeJSON tests JSON sanitization
func TestSanitizeJSON(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name     string
		input    string
		expected map[string]interface{}
	}{
		{
			name:  "Simple JSON with PII",
			input: `{"email":"user@example.com","orderId":"ORD-123"}`,
			expected: map[string]interface{}{
				"email":   "[REDACTED]",
				"orderId": "ORD-123",
			},
		},
		{
			name:  "Nested JSON",
			input: `{"user":{"email":"user@example.com","name":"John Doe"},"orderId":"ORD-456"}`,
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"email": "[REDACTED]",
					"name":  "[REDACTED]",
				},
				"orderId": "ORD-456",
			},
		},
		{
			name:  "JSON with array",
			input: `{"emails":["user1@example.com","user2@example.com"],"productId":"PROD-123"}`,
			expected: map[string]interface{}{
				"emails": []interface{}{
					"[REDACTED]",
					"[REDACTED]",
				},
				"productId": "PROD-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := s.SanitizeJSON([]byte(tt.input))
			if err != nil {
				t.Fatalf("SanitizeJSON failed: %v", err)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("Failed to unmarshal result: %v", err)
			}

			// Check specific fields
			if tt.name == "Simple JSON with PII" {
				if result["email"] != "[REDACTED]" {
					t.Error("Expected email to be redacted")
				}
				if result["orderId"] != "ORD-123" {
					t.Error("Expected orderId to be preserved")
				}
			}
		})
	}
}

// TestSanitizeJSONInvalid tests SanitizeJSON with invalid JSON
func TestSanitizeJSONInvalid(t *testing.T) {
	s := NewDefault()

	_, err := s.SanitizeJSON([]byte(`{invalid json}`))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

// TestSanitizeStruct tests struct sanitization with various types
func TestSanitizeStruct(t *testing.T) {
	s := NewDefault()

	type Address struct {
		Street     string `json:"street"`
		City       string `json:"city"`
		PostalCode string `json:"postalCode"`
	}

	type User struct {
		Email    string            `json:"email"`
		FullName string            `json:"fullName"`
		Age      int               `json:"age"`
		Active   bool              `json:"active"`
		Balance  float64           `json:"balance"`
		Address  Address           `json:"address"`
		Tags     []string          `json:"tags"`
		Metadata map[string]string `json:"metadata"`
		OrderID  string            `json:"orderId"`
	}

	user := User{
		Email:    "user@example.com",
		FullName: "John Doe",
		Age:      30,
		Active:   true,
		Balance:  100.50,
		Address: Address{
			Street:     "123 Main St",
			City:       "Singapore",
			PostalCode: "123456",
		},
		Tags: []string{"premium", "verified"},
		Metadata: map[string]string{
			"source": "web",
			"email":  "another@example.com",
		},
		OrderID: "ORD-789",
	}

	result := s.SanitizeStruct(user)

	// Check PII is redacted
	if result["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
	if result["fullName"] == "John Doe" {
		t.Error("Expected fullName to be redacted")
	}

	// Check nested struct
	if addr, ok := result["address"].(map[string]interface{}); ok {
		if addr["street"] == "123 Main St" {
			t.Error("Expected street to be redacted")
		}
	} else {
		t.Error("Expected address to be a map")
	}

	// Check non-PII is preserved (JSON unmarshals numbers as float64)
	if age, ok := result["age"].(float64); !ok || age != 30.0 {
		t.Errorf("Expected age to be preserved as 30.0, got %v (%T)", result["age"], result["age"])
	}
	if result["active"] != true {
		t.Error("Expected active to be preserved")
	}
	if result["orderId"] != "ORD-789" {
		t.Error("Expected orderId to be preserved")
	}

	// Check metadata map with PII
	if metadata, ok := result["metadata"].(map[string]interface{}); ok {
		if metadata["email"] == "another@example.com" {
			t.Error("Expected nested email in metadata to be redacted")
		}
		if metadata["source"] != "web" {
			t.Error("Expected source in metadata to be preserved")
		}
	}
}

// TestSanitizeStructNil tests SanitizeStruct with nil
func TestSanitizeStructNil(t *testing.T) {
	s := NewDefault()
	result := s.SanitizeStruct(nil)

	if len(result) != 0 {
		t.Error("Expected empty map for nil struct")
	}
}

// TestSanitizeStructPointer tests SanitizeStruct with pointer
func TestSanitizeStructPointer(t *testing.T) {
	s := NewDefault()

	type User struct {
		Email   string `json:"email"`
		OrderID string `json:"orderId"`
	}

	user := &User{
		Email:   "user@example.com",
		OrderID: "ORD-123",
	}

	result := s.SanitizeStruct(user)

	if result["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
	if result["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

// TestMatchesWithValidator tests the matches method with validators
func TestMatchesWithValidator(t *testing.T) {
	s := NewDefault()

	// Test IP address matching (has validator)
	if !s.contentMatcher.matches("192.168.1.1") {
		t.Error("Expected valid IP to match")
	}

	if !s.contentMatcher.matches("Text with IP 192.168.1.100 in it") {
		t.Error("Expected IP in text to match")
	}

	// Test credit card (validator disabled but pattern should match)
	if !s.contentMatcher.matches("4532-1234-5678-9010") {
		t.Error("Expected credit card pattern to match")
	}
}

// TestRegionSpecificPatterns tests region-specific patterns
func TestRegionSpecificPatterns(t *testing.T) {
	tests := []struct {
		name    string
		regions []Region
		content string
		match   bool
	}{
		{
			name:    "Singapore only - NRIC match",
			regions: []Region{Singapore},
			content: "S1234567A",
			match:   true,
		},
		{
			name:    "Singapore only - Malaysia MyKad no match",
			regions: []Region{Singapore},
			content: "901230-14-5678",
			match:   false,
		},
		{
			name:    "Malaysia only - MyKad match",
			regions: []Region{Malaysia},
			content: "901230-14-5678",
			match:   true,
		},
		{
			name:    "UAE only - IBAN match",
			regions: []Region{UAE},
			content: "AE07 0331 2345 6789 0123 456",
			match:   true,
		},
		{
			name:    "Thailand only - National ID match",
			regions: []Region{Thailand},
			content: "1-2345-67890-12-3",
			match:   true,
		},
		{
			name:    "Hong Kong only - HKID match",
			regions: []Region{HongKong},
			content: "A123456(7)",
			match:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewDefaultConfig().WithRegions(tt.regions...)
			s := New(config)

			matches := s.contentMatcher.matches(tt.content)
			if matches != tt.match {
				t.Errorf("Expected match=%v for %s, got %v", tt.match, tt.content, matches)
			}
		})
	}
}

// TestCustomContentPatterns tests custom content patterns
func TestCustomContentPatterns(t *testing.T) {
	customPattern := ContentPattern{
		Name:    "custom_id",
		Pattern: regexp.MustCompile(`\bCUST-\d{6}\b`),
	}

	config := NewDefaultConfig()
	config.CustomContentPatterns = []ContentPattern{customPattern}

	s := New(config)

	// Test custom pattern matches
	if !s.contentMatcher.matches("CUST-123456") {
		t.Error("Expected custom pattern to match")
	}

	// Test redaction with custom pattern
	result := s.SanitizeField("customId", "CUST-789012")
	if result != "[REDACTED]" {
		t.Errorf("Expected custom ID to be redacted, got %s", result)
	}
}

// TestCustomFieldPatterns tests custom field patterns
func TestCustomFieldPatterns(t *testing.T) {
	config := NewDefaultConfig()
	config.CustomFieldPatterns = map[string][]string{
		"custom_sensitive": {"internalId", "internal_id", "secretCode"},
	}

	s := New(config)

	// Test custom field pattern matches
	result := s.SanitizeField("internalId", "SECRET-123")
	if result != "[REDACTED]" {
		t.Errorf("Expected custom field to be redacted, got %s", result)
	}

	result = s.SanitizeField("secretCode", "ABC-XYZ")
	if result != "[REDACTED]" {
		t.Errorf("Expected custom field to be redacted, got %s", result)
	}
}
