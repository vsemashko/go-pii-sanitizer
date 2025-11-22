package sanitizer

import (
	"strings"
	"testing"
	"time"
)

// Test metrics collection
type testMetrics struct {
	calls []MetricsContext
}

func (m *testMetrics) RecordSanitization(ctx MetricsContext) {
	m.calls = append(m.calls, ctx)
}

func TestMetricsCollection(t *testing.T) {
	metrics := &testMetrics{}
	config := NewDefaultConfig().WithMetrics(metrics)
	s := New(config)

	// Sanitize a field that should be redacted
	s.SanitizeField("email", "user@example.com")

	// Sanitize a field that should NOT be redacted
	s.SanitizeField("orderId", "ORD-123")

	// Check metrics were recorded
	if len(metrics.calls) != 2 {
		t.Errorf("Expected 2 metric calls, got %d", len(metrics.calls))
	}

	// Verify first call (email - should be redacted)
	if metrics.calls[0].FieldName != "email" {
		t.Errorf("Expected field name 'email', got '%s'", metrics.calls[0].FieldName)
	}
	if !metrics.calls[0].Redacted {
		t.Errorf("Expected email to be redacted")
	}
	if metrics.calls[0].PIIType != "email" {
		t.Errorf("Expected PII type 'email', got '%s'", metrics.calls[0].PIIType)
	}

	// Verify second call (orderId - should NOT be redacted)
	if metrics.calls[1].FieldName != "orderId" {
		t.Errorf("Expected field name 'orderId', got '%s'", metrics.calls[1].FieldName)
	}
	if metrics.calls[1].Redacted {
		t.Errorf("Expected orderId to NOT be redacted")
	}
	if metrics.calls[1].PIIType != "" {
		t.Errorf("Expected empty PII type, got '%s'", metrics.calls[1].PIIType)
	}

	// Verify duration is tracked
	if metrics.calls[0].Duration == 0 {
		t.Errorf("Expected non-zero duration")
	}
}

func TestMaxFieldLength(t *testing.T) {
	config := NewDefaultConfig().WithMaxFieldLength(10)
	s := New(config)

	// Test with long field value
	longValue := strings.Repeat("a", 100)
	result := s.SanitizeField("description", longValue)

	// Description should be redacted (it's in the PII list)
	if result != "[REDACTED]" {
		t.Errorf("Expected [REDACTED], got %s", result)
	}

	// The important part is that it didn't panic or fail due to long input
	// and the metrics would show original length
	metrics := &testMetrics{}
	s2 := New(NewDefaultConfig().WithMaxFieldLength(10).WithMetrics(metrics))
	s2.SanitizeField("description", longValue)

	if metrics.calls[0].ValueLength != 100 {
		t.Errorf("Expected value length 100, got %d", metrics.calls[0].ValueLength)
	}
}

func TestMaxContentLength(t *testing.T) {
	config := NewDefaultConfig().WithMaxContentLength(50)
	s := New(config)

	// Test with very long content that contains PII near the end
	longContent := strings.Repeat("safe text ", 10) + "user@example.com"
	result := s.SanitizeField("message", longContent)

	// Since MaxContentLength=50 and email is after position 100,
	// it won't be detected
	if result == "[REDACTED]" {
		t.Errorf("Expected content NOT to be redacted (email is beyond max length)")
	}

	// Test with PII within max length
	shortContent := "Contact: user@example.com"
	result2 := s.SanitizeField("message", shortContent)
	if result2 != "[REDACTED]" {
		t.Errorf("Expected content to be redacted, got: %s", result2)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name:        "Valid MaxFieldLength",
			config:      NewDefaultConfig().WithMaxFieldLength(1000),
			expectError: false,
		},
		{
			name:        "Valid MaxContentLength",
			config:      NewDefaultConfig().WithMaxContentLength(10000),
			expectError: false,
		},
		{
			name:        "Valid zero MaxFieldLength (unlimited)",
			config:      NewDefaultConfig().WithMaxFieldLength(0),
			expectError: false,
		},
		{
			name:        "Invalid negative MaxFieldLength",
			config:      NewDefaultConfig().WithMaxFieldLength(-1),
			expectError: true,
		},
		{
			name:        "Invalid negative MaxContentLength",
			config:      NewDefaultConfig().WithMaxContentLength(-100),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectError && err == nil {
				t.Errorf("Expected validation error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no validation error, got: %v", err)
			}
		})
	}
}

func TestThailandIDChecksum(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{
			name:  "Valid Thai ID with checksum",
			id:    "1-2345-67890-12-1", // Calculated valid checksum
			valid: true,
		},
		{
			name:  "Valid Thai ID without dashes",
			id:    "1234567890121",
			valid: true,
		},
		{
			name:  "Invalid Thai ID - wrong checksum",
			id:    "1-2345-67890-12-3",
			valid: false,
		},
		{
			name:  "Invalid Thai ID - wrong length",
			id:    "1-2345-67890-12",
			valid: false,
		},
		{
			name:  "Invalid Thai ID - contains letters",
			id:    "1-2345-67890-12-A",
			valid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validateThaiID(tc.id)
			if result != tc.valid {
				t.Errorf("validateThaiID(%s) = %v, want %v", tc.id, result, tc.valid)
			}
		})
	}
}

func TestThailandIDPatternMatching(t *testing.T) {
	s := NewForRegion(Thailand)

	// Valid Thai ID should be redacted
	validID := "1-2345-67890-12-1"
	result := s.SanitizeField("content", "My ID is "+validID)
	if result == "My ID is "+validID {
		t.Errorf("Valid Thai ID should be redacted")
	}

	// Invalid Thai ID should NOT be redacted (fails checksum)
	invalidID := "1-2345-67890-12-9"
	result2 := s.SanitizeField("content", "My ID is "+invalidID)
	if result2 != "My ID is "+invalidID {
		t.Errorf("Invalid Thai ID should not be redacted, got: %s", result2)
	}
}

func TestSanitizeJSONErrorHandling(t *testing.T) {
	s := NewDefault()

	// Test invalid JSON
	_, err := s.SanitizeJSON([]byte("not valid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "sanitizer:") {
		t.Errorf("Expected error to contain 'sanitizer:', got: %v", err)
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("Expected error to mention unmarshal, got: %v", err)
	}

	// Test valid JSON
	validJSON := []byte(`{"email":"user@example.com","orderId":"ORD-123"}`)
	result, err := s.SanitizeJSON(validJSON)
	if err != nil {
		t.Errorf("Expected no error for valid JSON, got: %v", err)
	}
	if !strings.Contains(string(result), "[REDACTED]") {
		t.Errorf("Expected email to be redacted in result: %s", string(result))
	}
}

func TestNoOpMetrics(t *testing.T) {
	// Test that NoOpMetrics doesn't panic
	noop := NoOpMetrics{}
	noop.RecordSanitization(MetricsContext{
		FieldName: "test",
		Duration:  time.Millisecond,
	})
	// If we get here without panic, test passed
}

func TestMetricsWithNilConfig(t *testing.T) {
	// Test that metrics work when config.Metrics is nil (default)
	s := NewDefault()

	// This should not panic even though no metrics collector is set
	s.SanitizeField("email", "user@example.com")
	// If we get here without panic, test passed
}

func TestBuilderMethodChaining(t *testing.T) {
	// Test that all new builder methods return *Config for chaining
	config := NewDefaultConfig().
		WithMaxFieldLength(1000).
		WithMaxContentLength(5000).
		WithMetrics(&testMetrics{}).
		WithRedact("customField").
		WithPreserve("safeField")

	if config.MaxFieldLength != 1000 {
		t.Errorf("Expected MaxFieldLength=1000, got %d", config.MaxFieldLength)
	}
	if config.MaxContentLength != 5000 {
		t.Errorf("Expected MaxContentLength=5000, got %d", config.MaxContentLength)
	}
	if config.Metrics == nil {
		t.Error("Expected Metrics to be set")
	}
}

func TestEmptyFieldWithMetrics(t *testing.T) {
	metrics := &testMetrics{}
	s := New(NewDefaultConfig().WithMetrics(metrics))

	// Empty values should not be redacted and should not generate metrics
	result := s.SanitizeField("email", "")
	if result != "" {
		t.Errorf("Expected empty string to remain empty")
	}

	// No metrics should be recorded for empty values
	if len(metrics.calls) != 0 {
		t.Errorf("Expected no metrics for empty value, got %d calls", len(metrics.calls))
	}
}
