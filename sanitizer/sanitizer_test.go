package sanitizer

import (
	"testing"
)

func TestSanitizeField_Singapore(t *testing.T) {
	s := NewForRegion(Singapore)

	tests := []struct {
		name       string
		fieldName  string
		value      string
		shouldMask bool
	}{
		{
			name:       "Singapore NRIC in content",
			fieldName:  "text",
			value:      "My NRIC is S1234567A",
			shouldMask: true,
		},
		{
			name:       "Singapore FIN",
			fieldName:  "text",
			value:      "FIN: F1234567N",
			shouldMask: true,
		},
		{
			name:       "Singapore phone",
			fieldName:  "text",
			value:      "+6591234567",
			shouldMask: true,
		},
		{
			name:       "NRIC field name",
			fieldName:  "nric",
			value:      "S1234567A",
			shouldMask: true,
		},
		{
			name:       "Non-PII",
			fieldName:  "orderId",
			value:      "ORD-12345",
			shouldMask: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField(tt.fieldName, tt.value)
			if tt.shouldMask && result == tt.value {
				t.Errorf("Expected value to be masked, but got original value: %s", result)
			}
			if !tt.shouldMask && result != tt.value {
				t.Errorf("Expected value to be preserved, but got: %s", result)
			}
			if tt.shouldMask && result != "[REDACTED]" {
				t.Errorf("Expected [REDACTED], got: %s", result)
			}
		})
	}
}

func TestSanitizeField_Malaysia(t *testing.T) {
	s := NewForRegion(Malaysia)

	tests := []struct {
		name       string
		fieldName  string
		value      string
		shouldMask bool
	}{
		{
			name:       "Malaysia MyKad with dashes",
			fieldName:  "text",
			value:      "IC: 901230-14-5678",
			shouldMask: true,
		},
		{
			name:       "Malaysia MyKad without dashes",
			fieldName:  "text",
			value:      "901230145678",
			shouldMask: true,
		},
		{
			name:       "Malaysia phone",
			fieldName:  "text",
			value:      "+60123456789",
			shouldMask: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField(tt.fieldName, tt.value)
			if tt.shouldMask && result == tt.value {
				t.Errorf("Expected value to be masked, but got original value: %s", result)
			}
		})
	}
}

func TestSanitizeField_UAE(t *testing.T) {
	s := NewForRegion(UAE)

	tests := []struct {
		name       string
		fieldName  string
		value      string
		shouldMask bool
	}{
		{
			name:       "UAE Emirates ID with dashes",
			fieldName:  "text",
			value:      "784-2020-1234567-1",
			shouldMask: true,
		},
		{
			name:       "UAE IBAN",
			fieldName:  "text",
			value:      "AE07 0331 2345 6789 0123 456",
			shouldMask: true,
		},
		{
			name:       "UAE phone",
			fieldName:  "text",
			value:      "+971501234567",
			shouldMask: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField(tt.fieldName, tt.value)
			if tt.shouldMask && result == tt.value {
				t.Errorf("Expected value to be masked, but got original value: %s", result)
			}
		})
	}
}

func TestSanitizeField_CommonPatterns(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name       string
		fieldName  string
		value      string
		shouldMask bool
	}{
		{
			name:       "Email in content",
			fieldName:  "description",
			value:      "Contact john@example.com for details",
			shouldMask: true,
		},
		{
			name:       "Email field name",
			fieldName:  "email",
			value:      "user@example.com",
			shouldMask: true,
		},
		{
			name:       "Phone field name",
			fieldName:  "phoneNumber",
			value:      "1234567890",
			shouldMask: true,
		},
		{
			name:       "Name field",
			fieldName:  "fullName",
			value:      "John Doe",
			shouldMask: true,
		},
		{
			name:       "Transaction description",
			fieldName:  "memo",
			value:      "Payment to vendor",
			shouldMask: true,
		},
		{
			name:       "Bank account field",
			fieldName:  "accountNumber",
			value:      "123456789",
			shouldMask: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField(tt.fieldName, tt.value)
			if tt.shouldMask && result == tt.value {
				t.Errorf("Expected value to be masked, but got original value: %s", result)
			}
			if !tt.shouldMask && result != tt.value {
				t.Errorf("Expected value to be preserved, but got: %s", result)
			}
		})
	}
}

func TestSanitizeField_Secrets(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name      string
		fieldName string
		value     string
	}{
		{"Password", "password", "secret123"},
		{"Token", "accessToken", "eyJhbGciOiJIUzI1NiIs..."},
		{"API Key", "apiKey", "sk_live_1234567890"},
		{"Secret", "secret", "my-secret-value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField(tt.fieldName, tt.value)
			if result != "[REDACTED]" {
				t.Errorf("Expected secret to be redacted, got: %s", result)
			}
		})
	}
}

func TestExplicitLists(t *testing.T) {
	config := NewDefaultConfig().
		WithRedact("customField").
		WithPreserve("name") // Explicitly preserve "name" even though it's a PII pattern

	s := New(config)

	// Should redact because it's in AlwaysRedact
	result := s.SanitizeField("customField", "some value")
	if result != "[REDACTED]" {
		t.Errorf("Expected customField to be redacted, got: %s", result)
	}

	// Should preserve because it's in NeverRedact, even though "name" is a PII pattern
	result = s.SanitizeField("name", "John Doe")
	if result != "John Doe" {
		t.Errorf("Expected name to be preserved due to NeverRedact, got: %s", result)
	}
}

func TestSanitizeMap(t *testing.T) {
	s := NewForRegion(Singapore)

	input := map[string]any{
		"orderId": "ORD-123",
		"email":   "user@example.com",
		"nric":    "S1234567A",
		"amount":  100.50,
		"user": map[string]any{
			"fullName": "John Doe",
			"phone":    "+6591234567",
		},
	}

	result := s.SanitizeMap(input)

	// Order ID should be preserved
	if result["orderId"] != "ORD-123" {
		t.Errorf("Expected orderId to be preserved, got: %v", result["orderId"])
	}

	// Email should be redacted
	if result["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}

	// NRIC should be redacted
	if result["nric"] == "S1234567A" {
		t.Error("Expected nric to be redacted")
	}

	// Amount should be preserved
	if result["amount"] != 100.50 {
		t.Errorf("Expected amount to be preserved, got: %v", result["amount"])
	}

	// Nested user object
	user := result["user"].(map[string]any)
	if user["fullName"] == "John Doe" {
		t.Error("Expected nested fullName to be redacted")
	}
	if user["phone"] == "+6591234567" {
		t.Error("Expected nested phone to be redacted")
	}
}

func TestRedactionStrategies(t *testing.T) {
	t.Run("Full redaction", func(t *testing.T) {
		s := New(NewDefaultConfig().WithStrategy(StrategyFull))
		result := s.SanitizeField("email", "user@example.com")
		if result != "[REDACTED]" {
			t.Errorf("Expected [REDACTED], got: %s", result)
		}
	})

	t.Run("Partial masking", func(t *testing.T) {
		config := NewDefaultConfig().
			WithStrategy(StrategyPartial).
			WithPartialMasking('*', 0, 4)
		s := New(config)

		result := s.SanitizeField("email", "user@example.com")
		// Should preserve last 4 characters: ".com"
		if result[len(result)-4:] != ".com" {
			t.Errorf("Expected last 4 chars to be '.com', got: %s", result)
		}
		if result[:4] != "****" {
			t.Errorf("Expected first chars to be masked, got: %s", result[:4])
		}
	})

	t.Run("Hash strategy", func(t *testing.T) {
		s := New(NewDefaultConfig().WithStrategy(StrategyHash))
		result := s.SanitizeField("email", "user@example.com")
		if !contains(result, "sha256:") {
			t.Errorf("Expected hash to contain 'sha256:', got: %s", result)
		}
	})

	t.Run("Remove strategy", func(t *testing.T) {
		config := NewDefaultConfig().WithStrategy(StrategyRemove)
		s := New(config)

		input := map[string]any{
			"email":   "user@example.com",
			"orderId": "ORD-123",
		}

		result := s.SanitizeMap(input)

		// Email field should be removed entirely
		if _, exists := result["email"]; exists {
			t.Error("Expected email field to be removed")
		}

		// Order ID should still exist
		if _, exists := result["orderId"]; !exists {
			t.Error("Expected orderId to exist")
		}
	})
}

func TestCreditCardValidation(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name       string
		value      string
		shouldMask bool
	}{
		{
			name:       "Credit card with spaces",
			value:      "4532 1234 5678 9010",
			shouldMask: true,
		},
		{
			name:       "Credit card no spaces",
			value:      "4532123456789010",
			shouldMask: true,
		},
		{
			name:       "Credit card with dashes",
			value:      "4532-1234-5678-9010",
			shouldMask: true,
		},
		{
			name:       "Not a credit card (too short)",
			value:      "1234 5678",
			shouldMask: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField("text", tt.value)
			if tt.shouldMask && result == tt.value {
				t.Errorf("Expected value to be masked, but got original: %s", result)
			}
			if !tt.shouldMask && result != tt.value {
				t.Errorf("Expected value to be preserved, but got: %s", result)
			}
		})
	}
}

func TestMaxDepth(t *testing.T) {
	config := NewDefaultConfig()
	config.MaxDepth = 2
	s := New(config)

	input := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": map[string]any{
					"email": "user@example.com",
				},
			},
		},
	}

	result := s.SanitizeMap(input)

	// Should stop at level 2, level 3 should not be sanitized
	level1 := result["level1"].(map[string]any)
	level2 := level1["level2"].(map[string]any)
	level3 := level2["level3"].(map[string]any)

	// Email at level 3 should not be sanitized due to max depth
	if level3["email"] != "user@example.com" {
		t.Error("Expected email at max depth to not be sanitized")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && containsHelper(s, substr)
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
